require 'octokit'
require 'yaml'
require 'json'
require 'httparty'
require 'net/smtp'
require 'sqlite3'
require 'bcrypt'
require 'securerandom'
require 'aws-sdk'
require 'stomp'
require 'open-uri'
require 'pry' # remove this when not needed

# When testing, there should be a stomp (rabbitmq) broker running, like so:
# sudo docker run -d -e RABBITMQ_NODENAME=my-rabbit --name rabbitmq -p 61613:61613 resilva87/docker-rabbitmq-stomp


class String
  # Strip leading whitespace from each line that is the same as the
  # amount of whitespace on the first line of the string.
  # Leaves _additional_ indentation on later lines intact.
  def unindent()
    gsub(/^#{self[/\A[ \t]*/]}/,'')
  end
end

class InvalidSegmentNumberError < StandardError; end
class InvalidCharacterError < StandardError; end

class BiocVersion
  @x = 0
  @y = 0
  @z = 0
  attr_reader :x, :y, :z

  def initialize(version_string)
    segs = version_string.strip.split('.')
    unless segs.length == 3
      raise InvalidSegmentNumberError
    end
    for seg in segs
      fail = false
      if seg.include? '-'
        fail = true
      end
      begin
        Integer(seg)
      rescue
        fail = true
      end
      if fail
        raise InvalidCharacterError
      end
    end
    @x = Integer(segs[0])
    @y = Integer(segs[1])
    @z = Integer(segs[2])
  end

  def compare(other)
    if @x > other.x
      return 1
    end
    if @x < other.x
      return -1
    end
    if @x == other.x
      if @y > other.y
        return 1
      end
      if @y < other.y
        return -1
      end
      if @y == other.y
        if @z > other.z
          return 1
        end
        if @z < other.z
          return -1
        end
        return 0
      end
    end

  end

end


class CoreConfig
  @@request_uri  = nil
  @@db = nil
  @@auth_config = nil
  @@labels = {
    AWAITING_MODERATION_LABEL: "1. awaiting moderation",
    REVIEW_IN_PROGRESS_LABEL: "2. review in progress",
    ACCEPTED_LABEL: "3a. accepted",
    DECLINED_LABEL: "3b. declined",

    VERSION_BUMP_LABEL: "VERSION BUMP REQUIRED",

    ABNORMAL_LABEL: "ABNORMAL",
    ERROR_LABEL: "ERROR",
    OK_LABEL: "OK",
    TIMEOUT_LABEL: "TIMEOUT",
    WARNINGS_LABEL: "WARNINGS",

    TESTING_LABEL: "TESTING"
  }
  def self.set_request_uri(request_uri)
    @@request_uri = request_uri
  end
  def self.request_uri
    @@request_uri
  end
  def self.set_db(db)
    @@db = db
  end
  def self.db
    @@db
  end
  def self.set_auth_config(auth_config)
    @@auth_config = auth_config
  end
  def self.auth_config
    @@auth_config
  end
  def self.labels
    @@labels
  end
end


module Core
  # here, define the repo we care about
  # and other stuff.
  # this repo must have bioc-issue-bot as a collaborator, and
  # must have a hook defined that points to this app and
  # pushes (at least) the "Issues"  and "Issue comments" events.
  # After 'registering' their package in our issues repo,
  # developers can then set up webhooks to send us push
  # notifications.
  # Also need to make sure that the repos has whatever
  # custom labels (defined on issues) that we make use
  # of in this script.
  # (See CoreConfig.labels definition)
  # See https://help.github.com/articles/creating-and-editing-labels-for-issues-and-pull-requests/

  CoreConfig.set_auth_config(YAML::load_file(File.join(File.dirname(__FILE__), "auth.yml" )))


  GITHUB_URL_REGEX = %r{https://github.com/[^/]+/[^ /\s]+}
  NEW_ISSUE_REPO = CoreConfig.auth_config['issue_repo']
  REQUIRE_PREAPPROVAL = CoreConfig.auth_config['require_preapproval']

  # FIXME - do authentication more often (on requests?) so it doesn't go stale?
  # Not sure yet if this is a problem.

  # A note about OAuth. When setting up the token, it must have
  # the 'public_repo' scope (and when we are testing using a private
  # repos, it must be an admin-level contributor to the repos, and have
  # "repo" scope).
  def Core.authenticate()
    Octokit.configure do |c|
      c.access_token = CoreConfig.auth_config['auth_key']
    end
  end


  Core.authenticate()

  dbfile = File.join(File.dirname(__FILE__), "db.sqlite3" )
  CoreConfig.set_db(SQLite3::Database.new dbfile)
  if (!File.exists? dbfile) or (File.size(dbfile) == 0)
    rows = CoreConfig.db.execute <<-SQL.unindent
      create table repos (
        id integer primary key,
        name varchar(255) unique not null,
        pw_hash varchar(255) not null,
        issue_number integer not null,
        login varchar(255)
      );
    SQL
  end

  def Core.get_repo_issue_number (repo)
    rows = CoreConfig.db.execute("select issue_number from repos where name = ?",
      repo.sub(/https:\/\/github.com\//i, ""))
    return nil if rows.empty?
    rows.first.first
  end

  def Core.get_repo_by_issue_number(issue_number)
    results_as_hash = CoreConfig.db.results_as_hash
    begin
      CoreConfig.db.results_as_hash = true
      rows = CoreConfig.db.execute("select * from repos where issue_number = ?",
        issue_number)
      return nil if rows.empty?
      return rows.first
    ensure
      CoreConfig.db.results_as_hash = results_as_hash
    end
  end

  def Core.get_repo_by_repo_name(repo_name)
    results_as_hash = CoreConfig.db.results_as_hash
    begin
      CoreConfig.db.results_as_hash = true
      rows = CoreConfig.db.execute("select * from repos where name = ?",
        repo_name)
      return nil if rows.empty?
      return rows.first
    ensure
      CoreConfig.db.results_as_hash = results_as_hash
    end
  end

  def Core.count_ssh_keys(repos)
    user_keys_url = repos.split("/")[0..3].join("/") + ".keys"
    return HTTParty.get(user_keys_url).response.body.lines.count
  end

  def Core.add_repos_to_db(repos, hash, issue_number, login)
    CoreConfig.db.execute "insert into repos (name, pw_hash, issue_number, login) values (?,?,?,?)",
      repos.sub(/https:\/\/github.com\//i, ""), hash, issue_number, login
  end

  def Core.is_spoof? (request)
    # we should use https and basic auth as described at
    # https://help.github.com/articles/what-ip-addresses-does-github-use-that-i-should-whitelist/#service-hook-ip-addresses
    # although I'm not sure exactly how this is supposed to work.
    # At that point, request.env['REQUEST_URI'] will start with 'https://'
    # (i guess) if https is available.
    # However, in development we don't have that yet. So use IP whitelisting.
    # Also, this is not ipv6 compatible.
    if request.env.has_key? 'HTTP_X_FORWARDED_FOR'
      ip = request.env['HTTP_X_FORWARDED_FOR']
    else
      ip = request.env['REMOTE_ADDR']
    end
    return false if request.env.has_key? "HTTP_HOST" and
      ["127.0.0.1", "localhost"].include? request.env['HTTP_HOST']
    return false if ip == "127.0.0.1" # allow local testing
    regex = %r{^192\.30\.25[2345]\.}
    ip !~ regex
  end

  def Core.handle_post(request)
    if CoreConfig.request_uri.nil?
      CoreConfig.set_request_uri(request.base_url)
    end
    if Core.is_spoof? request
      puts "Unknown IP address"
      return [400, "Unknown IP address"]
    end
    begin
      json = request.body.read
      obj = JSON.parse json
    rescue JSON::ParserError
      return [400, "Failed to parse JSON"]
    end
    if (obj.has_key? 'zen')
      return [200, "ping received, Bioconductor/Contributions webhook ok"]
    end
    if (!obj.has_key? 'action') and (!obj.has_key? 'ref')
      return [400, "Only push, issue, and issue comment event hooks supported"]
    end
    if obj.has_key? 'ref'
      return Core.handle_push(obj)
    end
    if obj.has_key? 'action' and obj['action'] == "created"
      return Core.handle_issue_comment(obj)
    end
    if obj.has_key? 'action' and obj['action'] == "labeled"
      return Core.handle_issue_label_added(obj)
    end
    if obj['repository']['full_name'] != Core::NEW_ISSUE_REPO
      puts "Unknown repository #{obj['repository']['full_name']}"
      return [400, "Unknown repository"]
    end
    if obj.has_key? 'action' and  obj['action'] == "opened"
      return Core.handle_new_issue(obj)
    end
    [200, 'Post handled']
  end

  def Core.handle_issue_comment(obj)
    # TODO implement
    # issue comments may be used to submit additional packages
    # (such as experiment data packages) to be reviewed together
    # with the main package.
    # Be sure and ignore all comments posted by this bot itself.
    login = obj['comment']['user']['login']
    if login == Octokit.user.login
      return "ignoring a comment that I made myself."
    end
    if login != obj['issue']['user']['login']
      return "ignoring comment that's not from the creator of the issue."
    end
    comment = obj['comment']['body']
    lines = comment.split("\n")
    pkg_line = lines.detect{|i| i =~ /^AdditionalPackage: /}
    if pkg_line.nil?
      return "comment did not contain AdditionalPackage: tag"
    end
    match = pkg_line.scan(Core::GITHUB_URL_REGEX)
    if match.empty?
      return "no github URL in AdditionalPackage: line"
    end
    issue_state = obj['issue']['state']
    labels = obj['issue']['labels'].map{|i| i['name']}
    build_ok1 = (issue_state == "open" and
      labels.include? CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL])
    build_ok2 = (issue_state == "closed" and
      labels.include? CoreConfig.labels[:TESTING_LABEL])
    issue_number = obj['issue']['number']
    unless build_ok1 or build_ok2
      msg =  "Can't build unless issue is open and '#{CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]}' label is present, or issue is closed and '#{CoreConfig.labels[:TESTING_LABEL]}' label is present."
      Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, msg)
      return msg
    end



    full_repos_url = match.first.strip
    repos_url = full_repos_url.sub("https://github.com/", "")
    unless Core.repo_exists_in_github? (repos_url) # github url points to nonexistent repos
      return Core.handle_repo_does_not_exist(repos_url, issue_number, login,
      close=false)
    end
    description = Core.get_description_file(repos_url)
    if description.nil?
      return Core.handle_no_description_file(full_repos_url, issue_number, login,
        close=false)
    end
    existing_issue_number = Core.get_repo_issue_number(repos_url)
    if not existing_issue_number.nil?
      return Core.handle_existing_issue(existing_issue_number, issue_number, login,
        close=false)
    end

    Core.add_repos_to_db(repos_url, "no_hash_needed", issue_number, login)
    Core.start_build(repos_url, issue_number)
    msg = "Starting build on additional package #{full_repos_url}."
    msg_full= <<-END.unindent
    Hi @#{login},

    #{msg}

    **IMPORTANT**: Please read [the instructions][1] for setting up a
    push hook on your repository, or further changes to your
    additional package repository will NOT trigger a new build.

    The DESCRIPTION file of this additional package is:

    ```
    #{description}
    ```
    [1]: https://github.com/#{Core::NEW_ISSUE_REPO}/blob/master/CONTRIBUTING.md
    END
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, msg_full)
    return msg
  end

  # FIXME This checks if our DB already has a row with the same repos name.
  # We should also check if GitHub already has a repo with this name.
  def Core.handle_existing_issue(existing_issue_number, issue_number, login,
      close=true)
    comment= <<-END.unindent
      Dear @#{login} ,

      You (or someone) has already posted that repository to our tracker.

      See https://github.com/#{Core::NEW_ISSUE_REPO}/issues/#{existing_issue_number}

      You cannot post the same repository more than once.

      If you would like this repository to be linked to issue number: #{issue_number},
      Please contact a Bioconductor Core Member.
    END
    if close
      comment += "I am closing this issue."
      Core.close_issue(issue_number)
    end
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return "duplicate issue"
  end

  # When you want to close an issue, use this.
  def Core.close_issue(issue_number, issue=nil)
    unless Core.is_authenticated?
      Core.authenticate
    end
    if issue.nil?
      issue = Octokit.issue(Core::NEW_ISSUE_REPO, issue_number)
    end
    title = issue['title']
    title = "(inactive) " + title unless title.start_with? "(inactive) "
    unless title == issue['title']
      Octokit.update_issue(Core::NEW_ISSUE_REPO, issue_number,
      title, issue['body'])
    end
    # This should be the only place where Octokit.close_issue is called directly.
    Octokit.close_issue(Core::NEW_ISSUE_REPO, issue_number)
  end

  def Core.handle_issue_label_added(obj)
    login = obj['issue']['user']['login']
    if login == Octokit.user.login
      return "ignoring a comment that i made myself."
    end
    issue_number = obj['issue']['number']
    if obj["label"]["name"] == CoreConfig.labels[:ACCEPTED_LABEL]
      package_repos =
        obj['issue']['body'].split("\n").
        find {|i| i.start_with? "- Repository: "}.sub("- Repository: ", "").
        strip
      package = obj['issue']['title']

      recipient_email = CoreConfig.auth_config["email_recipient"]
      recipient_name = CoreConfig.auth_config["email_recipient_name"]
      from_email = "bioc-github-noreply@bioconductor.org"
      from_name = "Bioconductor Issue Tracker"
      subject = "Package #{package} (issue #{issue_number}) has been accepted."
      message= <<-END.unindent
        Dear Bioconductor package administrator,

        Package '#{package}' accepted. Please add this package to
        version control.

        Issue: https://github.com/#{Core::NEW_ISSUE_REPO}/issues/#{issue_number}

        Source: #{package_repos}

        Thanks,

        #{Octokit.user.login}
      END
      Core.send_email("#{from_name} <#{from_email}>",
        "#{recipient_name} <#{recipient_email}>",
        subject,
        message)

      comment= <<-END.unindent
        Your package has been accepted. It will be added to the
        Bioconductor Git repository and nightly builds. Additional
        information will be sent to the maintainer email address in
        the next several days.

        Thank you for contributing to Bioconductor!
      END
      Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)

      return "ok, package accepted"
    elsif obj['label']['name'] == CoreConfig.labels[:DECLINED_LABEL]
      Core.close_issue(issue_number)
      return "ok, package declined, issue closed"
    end
    return "handle_issue_label_added"
  end


  def Core.handle_push(obj)
    repos = obj['repository']['full_name']
    db_record = get_repo_by_repo_name(repos)
    if db_record.nil?
      return "Sorry, you haven't told us about this repository, please
      go to https://github.com/#{Core::NEW_ISSUE_REPO}/issues/new ."
    end
    issue_number = db_record['issue_number']
    issue = Octokit.issue(Core::NEW_ISSUE_REPO, issue_number)
    repos_obj = Octokit.repository(repos)
    default_branch = repos_obj['default_branch']
    push_branch = obj['ref'].sub("refs/heads/", "")
    unless push_branch == default_branch
      return "#{push_branch} branch ignored, only handling #{default_branch}"
    end

    build_ok = false
    labels = Octokit.labels_for_issue(Core::NEW_ISSUE_REPO, issue_number).
      map{|i| i.name}
    if issue['state'] = "open" and labels.include? CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]
      build_ok = true
    elsif issue['state'] = "closed" and labels.include? CoreConfig.labels[:TESTING_LABEL]
      build_ok = true
    end
    if build_ok
      labels = Octokit.labels_for_issue(
        CoreConfig.auth_config['issue_repo'], issue_number)
      has_version_bump_label = labels.find {
        |i| i.name == CoreConfig.labels[:VERSION_BUMP_LABEL]
      }

      unless Core.version_has_bumped? obj
        if not has_version_bump_label
          Octokit.add_labels_to_an_issue(
            CoreConfig.auth_config['issue_repo'], issue_number,
            [CoreConfig.labels[:VERSION_BUMP_LABEL]])
        end
        return "version bump required"
      end

      if has_version_bump_label
        Octokit.remove_label(
          CoreConfig.auth_config['issue_repo'], issue_number,
          CoreConfig.labels[:VERSION_BUMP_LABEL])
      end

      # FIXME - this might cause too much noise (emails) in the issue,
      # it would be better to show commit info in the same comment
      # as the link to the build report. In order to do that, we have
      # to persist the push info somehow and retrieve it when we are
      # ready to post the build report (note that this is done from
      # staging.bioconductor.org whereas this app runs on
      # issues.bioconductor.org).
      comment= "Received a valid push; starting a build. Commits are:\n\n"
      for commit in obj['commits']
        msg = commit['message'].gsub(/\n/, " ")
        msg_display_len = 50
        if msg.length > msg_display_len
          msg = msg[0...msg_display_len] + "..."
        end
        comment += "[#{commit['id'][0...7]}](#{commit['url']}) #{msg}\n"
      end
      Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)

      Core.start_build(repos, issue_number)
      return "OK starting build"
    else
      return "can't build unless issue is open and has the '#{CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]}'
      label, or is closed and has the '#{CoreConfig.labels[:TESTING_LABEL]}' label."
    end
  end

  def Core.version_has_bumped? (push_obj)
      repos = push_obj['repository']['full_name']
      before = push_obj['before']
      after = push_obj['after']
      comp = Octokit.compare(repos, before, after)
      desc = comp[:files].find{|i| i[:filename] == "DESCRIPTION"}
      return false if desc.nil?
      return Core.does_patch_have_version_bump? (desc[:patch])
  end

  def Core.does_patch_have_version_bump? (patch)
    lines = patch.split /\r|\n|\r\n/
    lines.reject! {|i| i.empty? }
    oldversion = lines.find {|i| i.start_with? "-Version:"}
    return false if oldversion.nil?
    oldversion = oldversion.sub("-Version:", "").strip
    newversion = lines.find {|i| i.start_with? "+Version:"}
    return false if newversion.nil?
    newversion = newversion.sub("+Version:", "").strip
    begin
      old_v = BiocVersion.new(oldversion)
      new_v = BiocVersion.new(newversion)
    rescue
      return false
    end
    return (new_v.compare(old_v) == 1)
  end

  def Core.handle_no_repos_url(issue_number, login)
    comment= <<-END.unindent
      Dear @#{login} ,

      I couldn't find a GitHub repository URL in your issue text!
      Please include a github repository URL, it should look like this:

      https://github.com/username/reponame

      I am closing this issue. Please try again with a new issue.
    END
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    Core.close_issue(issue_number)
    return "no github URL in new issue comment"
  end


  def Core.handle_multiple_urls(issue_number, login)
    comment = <<-END.unindent
      Dear @#{login} ,

      I found more than one GitHub URL in your issue. Please make sure there
      is only one, it should look like:

      https://github.com/username/reponame

      I am closing this issue. Please try again with a new issue.
    END
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    Core.close_issue(issue_number)
    return "found multiple URLs in new issue comment"
  end

  def Core.repo_exists_in_github? (repos_url)
    begin
      repos = Octokit.repository(repos_url)
      return true
    rescue Octokit::NotFound
      return false
    end
  end

  def Core.handle_bioconductor_mirror_repo(issue_number, login)
    comment = <<-END.unindent
      Dear @#{login} ,

      Sorry, we don't build packages in the `Bioconductor-mirror`
      organization. These packages have already been accepted
      into _Bioconductor_.

      This issue will now be closed.
    END
    Core.close_issue(issue_number)
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return "Won't build repos in the Bioconductor-mirror organization."
  end


  def Core.handle_repo_does_not_exist(repos_url, issue_number, login, close=true)
    comment = <<-END.unindent
      Dear @#{login} ,

      There is no repository called https://github.com/#{repos_url} .
      You must submit the url to a valid, public GitHub repository.
    END
    if close
      comment += "I am closing this issue. Please try again with a new issue."
      Core.close_issue(issue_number)
    end
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return "repos does not exist"
  end

  def Core.get_description_response(repos_url)
    repos_url = repos_url.sub(/\.git$/, "")
    repos = Octokit.repository(repos_url)
    default_branch = repos['default_branch']
    desc_url = "https://raw.githubusercontent.com/#{repos_url}/#{default_branch}/DESCRIPTION"
    return HTTParty.get(desc_url)
  end

  def Core.has_description_file?(repos_url)
    response = Core.get_description_response(repos_url)
    return response.code == 200
  end

  def Core.get_description_file(repos_url)
    response = Core.get_description_response(repos_url)
    return nil unless response.code == 200
    return response.body
  end

  def Core.handle_no_description_file(full_repos_url, issue_number, login, close=true)
    full_repos_url = full_repos_url.sub(/\.git$/, "")
    comment = <<-END.unindent
      Dear @#{login} ,

      I could not find a DESCRIPTION file in the default branch of the
      GitHub repository at #{full_repos_url} . This repository should
      contain an R package.

    END
    if close
      comment += "I am closing this issue. Please try again with a new issue."
      Core.close_issue(issue_number)
    end
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return "no description file found!"
  end

  def Core.handle_package_name_mismatch(repos_url, package_name,
        issue_number, login, close=true)
    repos_package_name = repos_url.split('/').last
    comment = <<-END.unindent
      Dear @#{login},

      The package repository name, '#{repos_package_name}', differs
      from the package name in the DESCRIPTION file, '#{package_name}'.

      Please rename your repository, and submit a new
      issue. Alternatively, change the Package: field in the
      DESCRIPTION file to match the name of the repository.

    END
    if close
      comment += "I am closing this issue. Please try again with a new issue."
      Core.close_issue(issue_number)
    end
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return "DESCRIPTION and issue package name differ!"
  end

  def Core.handle_preapproval(repos, issue_number, password)
    recipient_email = CoreConfig.auth_config["email_recipient"]
    recipient_name = CoreConfig.auth_config["email_recipient_name"]
    from_email = "bioc-github-noreply@bioconductor.org"
    from_name = "Bioconductor Issue Tracker"
    issue = Octokit.issue(Core::NEW_ISSUE_REPO, issue_number)
    Octokit.add_labels_to_an_issue(Core::NEW_ISSUE_REPO, issue_number,
      [CoreConfig.labels[:AWAITING_MODERATION_LABEL]])
    msg = <<-END.unindent
      Hi devteam,

      Repository: https://github.com/#{repos}

      Issue:  https://github.com/#{Core::NEW_ISSUE_REPO}/issues/#{issue_number}

      Approve: #{CoreConfig.request_uri}/moderate_new_issue/#{issue_number}/approve/#{password}

      Reject: #{CoreConfig.request_uri}/moderate_new_issue/#{issue_number}/reject/#{password}

      A github repository has been submitted as a new issue to the
      tracker with the title '#{issue['title']}' and I'd like you to
      take a quick look at it before we let it into the single package
      builder.

      Make sure that

      1. It looks like a package that is intended for _Bioconductor_,
         and not one that is trying to use the single package builder
         for free; and

      2. It does not seem like a malicious package that will try to
         cause damage to our build system. Don't check exhaustively
         for this because there are many ways to hide badness.

      Please approve or reject the package.

      Only one person needs to do this. The web page will tell you if
      it has been done already.

      After the package has been approved (or rejected) once, the
      remaining steps will be handled automatically.

      The contributor will be told to read the guidelines and try
      again.  You can always post a more personalized message by going
      to the issue.  You can then manually allow the package to
      be built by adding the
      "#{CoreConfig.labels[:AWAITING_MODERATION_LABEL]}" label to the
      issue. To manually reject the issue, just close it.

      Please don't reply to this email.

      Thanks,

      The Bioconductor/GitHub issue tracker.
    END
    Core.send_email("#{from_name} <#{from_email}>",
      "#{recipient_name} <#{recipient_email}>",
      "Action required: Please allow/reject new package submitted to tracker (issue ##{issue_number}: #{issue[:title]})",
      msg)
  end

  def Core.handle_new_issue(obj)
    puts "got a new issue!"
    login = obj['issue']['user']['login']
    body = obj['issue']['body']
    match = body.scan(Core::GITHUB_URL_REGEX)
    issue_number = obj['issue']['number']
    if match.empty? # no github url present
      return Core.handle_no_repos_url(issue_number, login)
    elsif match.length > 1 # multiple github urls present
      return Core.handle_multiple_urls(issue_number, login)
    else # there is just one URL
      full_repos_url = match.first.strip
      repos_url = full_repos_url.sub("https://github.com/", "")
      unless Core.repo_exists_in_github? (repos_url) # github url points to nonexistent repos
        return Core.handle_repo_does_not_exist(repos_url, issue_number, login)
      end
      if repos_url.start_with? "Bioconductor-mirror"
        return Core.handle_bioconductor_mirror_repo(issue_number, login)
      end
      description = Core.get_description_file(repos_url)
      if description.nil?
        return Core.handle_no_description_file(full_repos_url, issue_number, login)
      end
      package_name = description.scan(/^Package: *(.+)/).first.first.strip
      unless (repos_url.split("/").last == package_name) or
            (package_name == "BioThingsClient") # special case!
        return Core.handle_package_name_mismatch(
                 repos_url, package_name, issue_number, login
               )
      end
      # looking good so far....
      # FIXME - also make sure it's not a repos in Bioconductor-mirror
      # or another one that we definitely know about referring
      # to a package that has already been accepted.

      existing_issue_number = Core.get_repo_issue_number(repos_url)
      if not existing_issue_number.nil?
        return Core.handle_existing_issue(existing_issue_number, issue_number, login)
      end

      password = SecureRandom.hex(20)
      hash = BCrypt::Password.create(password)
      n_ssh_keys = Core.count_ssh_keys(full_repos_url)
      Core.add_repos_to_db(repos_url, hash, issue_number, login)
      if REQUIRE_PREAPPROVAL
        comment= <<-END
          Hi @#{login}

          Thanks for submitting your package. We are taking a quick
          look at it and you will hear back from us soon.

          The DESCRIPTION file for this package is:

          ```
          #{description}
          ```

        END
        if (n_ssh_keys == 0)
          add_keys_comment= <<-END

            Consider adding SSH keys to your GitHub account. SSH keys
            will are used to control access to accepted _Bioconductor_
            packages. See [these instructions][1] to add SSH keys to
            your GitHub account.

            [1]: https://help.github.com/articles/adding-a-new-ssh-key-to-your-github-account/

          END
          comment += add_keys_comment
        end
        comment = comment.unindent

        Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
        return Core.handle_preapproval(repos_url, issue_number, password)
      else
        comment = <<-END.unindent
          Thanks, @#{login} !

          You submitted a single valid GitHub URL that points to an R
          package (it has a DESCRIPTION file).

          A reviewer has been assigned, and your package will be
          processed by them.

          **IMPORTANT**: Please read [the instructions][1] for setting
          up a push hook on your repository, or further changes to
          your repository will NOT trigger a new build.

          The DESCRIPTION file of your package is:

          ```
          #{description}
          ```
          [1]: (https://github.com/#{Core::NEW_ISSUE_REPO}/blob/master/CONTRIBUTING.md)
        END
        Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
        Octokit.add_labels_to_an_issue(Core::NEW_ISSUE_REPO, issue_number,
          [CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]])
        assignee = Core.get_issue_assignee(issue_number)
        unless assignee.nil?
          Octokit.update_issue(Core::NEW_ISSUE_REPO, issue_number, assignee: assignee)
        end
        Core.start_build(repos_url, issue_number)
      end
    end
    return "handled new issue"
  end

  def Core.get_issue_assignee(issue_number)
    issue_number = issue_number.to_i # necessary?
    # The ID for the 'Core' team should not change, but if it does you can look up
    # teams with
    # Octokit.organization_teams("Bioconductor")
    team_number = CoreConfig.auth_config['reviewer_team_number']
    mems = Octokit.team_members(team_number).
           delete_if{|x| x[:login] == 'gr22772'}
    logins = mems.map{|i| i[:login]}.sort # i think they are already sorted, but...
    # if this is issue #1 it's a special case:
    if issue_number == 1
      return logins.first
    end
    # find the previous issue and see who it was assigned to.
    # it's possible there is more than one unassigned
    # so look up all issues, sorted by creation (ascending):
    issues = Octokit.issues(Core::NEW_ISSUE_REPO, {sort: 'created',
      direction:'desc', state: 'all'})
    last_issue_assignee = nil
    # just in case this issue has already been assigned, don't change the assignee:
    this_issue = issues.find{|i| i[:number] == issue_number}
    if (!this_issue.nil?) and (!this_issue[:assignee].nil?)
      return nil # signal the caller not to change assignee
    end

    for issue in issues
      next if issue[:number] >= issue_number
      next if issue[:assignee].nil?
      last_issue_assignee = issue[:assignee][:login]
      break
    end
    if last_issue_assignee.nil? # no issues were assigned
      return logins.first
    end
    memhash = {}
    logins.each_with_index do |login, i|
      memhash[login] = i
    end
    last_issue_index = memhash[last_issue_assignee]
    if last_issue_index == (logins.length() -1)
      return logins.first
    else
      return logins[last_issue_index + 1]
    end
  end


  def Core.send_email(from, to, subject, message)
    aws = CoreConfig.auth_config['aws']
    ses = Aws::SES::Client.new(
      region: aws['region'],
      access_key_id: aws['aws_access_key_id'],
      secret_access_key: aws['aws_secret_access_key']
    )
    ses.send_email({
      source: from, # required
      destination: { # required
        to_addresses: [to]
      },
      message: { # required
        subject: { # required
          data: subject, # required
          charset: "UTF-8",
        },
        body: { # required
          text: {
            data: message, # required
            charset: "UTF-8",
          }#,
          # html: {
          #   data: "<p>i am the <b>body</b></p>", # required
          #   charset: "UTF-8",
          # },
        },
      }#,
      #reply_to_addresses: ["me@bioconductor.org"],
      # return_path: "complaints@bioconductor.org"#,
      # source_arn: "arn:aws:iam::555219204010:user/dtenenba",
      # return_path_arn: "arn:aws:iam::555219204010:user/dtenenba",
    })
  end

  def Core.moderate_new_issue(issue_number, action, password)
    unless Core.is_authenticated?
      return "oops, there's a problem with GitHub authentication!"
    end
    repos = Core.get_repo_by_issue_number(issue_number)
    if repos.nil?
      return "oops, i am not familiar with that issue/repository."
    end

    correct_password = BCrypt::Password.new(repos['pw_hash'])
    unless correct_password == password
      return "wrong password, you are not authorized"
    end
    unless ['approve', 'reject'].include? action
      return "all i know how to do is approve and reject."
    end
    issue = Octokit.issue(CoreConfig.auth_config['issue_repo'], issue_number)
    if issue['state'] == "closed"
      return("this issue has already been rejected (and closed).")
    end
    labels = Octokit.labels_for_issue(CoreConfig.auth_config['issue_repo'], issue_number)
    if labels.find {|i| i.name == CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]}
      return "this issue has already been marked '#{CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]}'."
    end
    if action == "reject"
      comment= <<-END.unindent
        This issue was deemed inappropriate for our issue tracker by a
        member of the Bioconductor team.

        This issue tracker is intended only for packages which are
        being submitted for consideration by Bioconductor.

        Any other use of the tracker is not approved.  If you feel
        this designation is in error, please [send us email][1] and
        include the URL of this issue.

        This issue will now be closed.

        [1]: maintainer@bioconductor.org
      END
      Octokit.add_comment(CoreConfig.auth_config['issue_repo'], issue_number,
        comment)
      Core.close_issue(issue_number, issue)
      return "ok, issue rejected."
    else
      comment= <<-END.unindent
        A reviewer has been assigned to your package Learn [What to Expect][2]
        during the review process.

        **IMPORTANT**: Please read [the instructions][1] for setting
        up a push hook on your repository, or further changes to your
        repository will NOT trigger a new build.

        [1]: https://github.com/#{Core::NEW_ISSUE_REPO}/blob/master/CONTRIBUTING.md#adding-a-web-hook
        [2]: https://github.com/Bioconductor/Contributions#what-to-expect
      END
      Octokit.add_comment(CoreConfig.auth_config['issue_repo'], issue_number,
        comment)
      Octokit.remove_label(CoreConfig.auth_config['issue_repo'],
        issue_number, CoreConfig.labels[:AWAITING_MODERATION_LABEL])
      Octokit.add_labels_to_an_issue(CoreConfig.auth_config['issue_repo'],
        issue_number, [CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]])
      # FIXME  start a build!
      repos_url = "https://github.com/#{repos['name']}"
      assignee = Core.get_issue_assignee(issue_number)
      unless assignee.nil?
        Octokit.update_issue(Core::NEW_ISSUE_REPO, issue_number, assignee: assignee)
      end
      Core.start_build(repos_url, issue_number)
      # FIXME return to github issue, rather than text string
      return "ok, marked issue as 'ok_to_build', starting a build..."
    end
    return "ok so far"

  end

  def Core.is_authenticated?
    begin
      Octokit.user
      return true
    rescue
      return false
    end
  end


  def Core.get_bioc_config_yaml()
    yaml_content = open("http://master.bioconductor.org/config.yaml"){|f| f.read}
    YAML::load(yaml_content)
  end


  def Core.start_build(repos_url, issue_number)
    segs = repos_url.sub(/\/$|\.git$/, '').split('/')
    repos_url = "https://github.com/" +
      repos_url unless repos_url.downcase.start_with?("https://github.com")
    pkgname = segs.last
    now = Time.now
    # FIXME this is NOT pacific time unless we explicitly
    # set that time zone on the host. So we should force this
    # to be pacific time (and eventually think about using
    # either Eastern time or UTC throughout).
    tzname = now.zone
    if tzname == "PDT"
        offset = "0700"
    else # PST
        offset = "0800"
    end
    timestamp1 = now.strftime("%Y%m%d%H%M%S")
    timestamp2 = now.strftime("%a %b %d %Y %H:%M:%S")
    timestamp2 = timestamp2 + " GMT-#{offset} (#{tzname})"
    obj = {}
    obj['job_id'] = "#{pkgname}_#{timestamp1}"
    obj['time'] = timestamp2
    obj['client_id'] = "single_package_builder_github:#{issue_number}:#{pkgname}"
    obj['force'] = true
    config_yaml = Core.get_bioc_config_yaml()
    devel_version = config_yaml['single_package_builder']['bioc_version']
    obj['bioc_version'] = devel_version
    obj['r_version'] = config_yaml['single_package_builder']['r_version']
    obj['svn_url'] = repos_url
    obj['repository'] = 'scratch'
    json = obj.to_json

    stomp = CoreConfig.auth_config['stomp']
    stomp_hash = {hosts: [{host: stomp['broker'], port: stomp['port']}]}
    # FIXME - if the broker is down or unreachable this will hang and make
    # the approver wait forever. Think of a more transactional
    # (everything succeeds or everything fails) approach, and this
    # part should maybe be in a separate thread with a timeout of
    # 5 seconds or so.
    client = Stomp::Client.new(stomp_hash)
    client.publish("/topic/buildjobs", json)
  end


end # end of Core module
