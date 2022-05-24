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
require 'open-uri'
require 'debian_control_parser'
require 'tmpdir'
require 'rgl/adjacency'
require 'rgl/traversal'
require 'rgl/connected_components'



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
    INACTIVE_LABEL: "3c. inactive",
    PREAPPROVED: "pre-check passed",
    PENDING_CHANGES: "3e. pending pre-review changes",
    NEED_INTEROP: "3d. needs interop",

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

  $LastCommitId = "initialize"

  GITHUB_URL_REGEX = %r{https://github.com/[^/]+/[^ /\s]+}
  NEW_ISSUE_REPO = CoreConfig.auth_config['issue_repo']
  REQUIRE_PREAPPROVAL = CoreConfig.auth_config['require_preapproval']

  # Version number checks
  # x.99.z valid syntax check
  PKG_VER_REGEX = %r{^[0-9]+[-\\.]99[-\\.][0-9]+$}
  # x should be 0 unless pre-release check
  PKG_VER_X_REGEX = %r{^[0]+}

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

  def Core.get_repo_issue_number(repo)
    rows = CoreConfig.db.execute("select issue_number from repos where name = ?",
      repo.sub(/https:\/\/github.com\//i, ""))
    return nil if rows.empty?
    rows.first.first
  end

  def Core.get_repo_issue_number_git(pkgname)
    call = "select issue_number from repos where name LIKE '%/" +  pkgname + "'"
    rows = CoreConfig.db.execute(call)
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

  # Count keys on login
  def Core.count_login_keys(login)
    login_keys_url = "https://github.com/" + login + ".keys"
    return HTTParty.get(login_keys_url).response.body.lines.count
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
    test = ip !~ regex
    if (test)
      regex = %r{^185\.199\.1(0[89]|1[01])\.}
      test = ip !~ regex
    end
    if (test)
      regex = %r{^140.82.1(1[23456789]|2[01234567])\.}
      test = ip !~ regex
    end
    test
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
    if (obj.has_key? 'ref') and (obj.has_key? 'after') and (obj['after'] != $LastCommitId)
      $LastCommitId = obj['after']
      return Core.handle_push(obj)
    end
    if (obj.has_key? 'ref') and (obj.has_key? 'after') and (obj['after'] == $LastCommitId)
        return [200, "repeated action"]
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
    if (obj.has_key? 'action') and  (obj['action'] == "reopened")
      return Core.handle_reopened_issue(obj)
    end
    if (obj.has_key? 'action') and  (obj['action'] == "closed")
      return Core.handle_closed_issue(obj)
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
    pkg_line = lines.detect{|i| i =~ /AdditionalPackage: /}
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
      close=true)
    end
    github_repo_name = Core.get_repo_name(repos_url)
    unless repos_url == github_repo_name
      return Core.handle_caps_check_failed(repos_url, github_repo_name,
      issue_number, login, close=false)
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
    pkgname = repos_url.partition('/').last
    existing_issue_number2 = Core.get_repo_issue_number_git(pkgname)
    if not existing_issue_number2.nil?
      return Core.handle_existing_issue2(existing_issue_number2, issue_number, login)
    end

    password = SecureRandom.hex(20)
    hash = BCrypt::Password.create(password)

    Core.add_repos_to_db(repos_url, hash, issue_number, login)

    comment= <<-END
      Hi @#{login},
      Thanks for submitting your additional package: #{full_repos_url}.
      We are taking a quick look at it and you will hear back from us soon.
    END
    comment = comment.unindent
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)

    return Core.handle_preapproval_additional_package(repos_url, issue_number, password)

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

  def Core.handle_existing_issue2(existing_issue_number, issue_number, login,
      close=true)
    comment= <<-END.unindent
      Dear @#{login} ,

      You (or someone) has already posted a repository with the same name to our tracker.

      See https://github.com/#{Core::NEW_ISSUE_REPO}/issues/#{existing_issue_number}

      You cannot post the same repository more than once and packages are not
      allowed to have the same name.

      If you would like this repository to be linked to issue number: #{issue_number},
      Please contact a Bioconductor Core Member.
    END
    if close
      comment += "I am closing this issue."
      Core.close_issue(issue_number)
    end
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return "duplicate name issue"
  end

  def Core.handle_closed_issue(obj)
    login = obj['issue']['user']['login']
    body = obj['issue']['body']
    issue_number = obj['issue']['number']
    issue = Octokit.issue(Core::NEW_ISSUE_REPO, issue_number)
    labels = Octokit.labels_for_issue(Core::NEW_ISSUE_REPO, issue_number).
               map{|i| i.name}
    if labels.include? CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]
      Octokit.remove_label(
        CoreConfig.auth_config['issue_repo'], issue_number,
        CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL])
    end
    return "handle closed issue"
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
    labels = Octokit.labels_for_issue(
      CoreConfig.auth_config['issue_repo'], issue_number)
    has_review_label = labels.find {
      |i| i.name == CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]
    }
    if has_review_label
      Octokit.remove_label(
        CoreConfig.auth_config['issue_repo'], issue_number,
        CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL])
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

        Package '#{package}' accepted.

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
        Bioconductor nightly builds.

        Thank you for contributing to Bioconductor!

        Reviewers for Bioconductor packages are volunteers from the Bioconductor
        community. If you are interested in becoming a Bioconductor package
	reviewer, please see [Reviewers Expectations][revexp].

        [revexp]: http://contributions.bioconductor.org/reviewer-resources-overview.html
      END
      Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)

      return "ok, package accepted"
    elsif obj['label']['name'] == CoreConfig.labels[:DECLINED_LABEL]
      Core.close_issue(issue_number)
      return "ok, package declined, issue closed"
    elsif obj['label']['name'] == CoreConfig.labels[:INACTIVE_LABEL]
      comment= <<-END.unindent
        This issue is being closed because there has been no progress
        for an extended period of time. You may reopen the issue when
        you have the time to actively participate in the review /
        submission process. Please also keep in mind that a package
        accepted to Bioconductor requires a commitment on your part to
        ongoing maintenance.

        Thank you for your interest in Bioconductor.
      END
      Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
      Core.close_issue(issue_number)
      return "ok, package inactive, issue closed"
    end
    return "handle_issue_label_added"
  end

  def Core.handle_git_push(request)
    begin
      json = request.body.read
      obj = JSON.parse json
    rescue JSON::ParserError
      return [400, "Failed to parse JSON"]
    end
    if (!obj.has_key? 'pkgname')
      return [400, "Request must include pkgname"]
    end
    if (!obj.has_key? 'commit_id')
      return [400, "Request must include commit_id"]
    end

    pkgname = obj['pkgname'].to_s
    commit_id = obj['commit_id'].to_s

    giturl = "https://git.bioconductor.org/packages/" + pkgname
    issue_number = get_repo_issue_number_git(pkgname)

    # figure out what to do...
    build_ok = false
    newpackage = false
    if !issue_number.nil?
      issue = Octokit.issue(Core::NEW_ISSUE_REPO, issue_number)
      labels = Octokit.labels_for_issue(Core::NEW_ISSUE_REPO, issue_number).
                 map{|i| i.name}
      if issue['state'] = "open" and labels.include? CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]
        build_ok = true
        newpackage = true
      elsif issue['state'] = "closed" and labels.include? CoreConfig.labels[:TESTING_LABEL]
        build_ok = true
        newpackage = true
      elsif labels.include? CoreConfig.labels[:ACCEPTED_LABEL]
        # when building ALL packges on commit
        # package issue number exists and already accepted into bioc
        #build_ok = true
      end
    # else
    #   # when building ALL packages on commit
    #   # older packages without issue_number
    #   build_ok = true
    end

    # ...now do it
    if build_ok
      if newpackage
        comment = "Received a valid push on git.bioconductor.org; starting a build for commit id: " + commit_id
        Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
      end
      Core.start_build(giturl, issue_number, commit_id, newpackage=newpackage)
      return [200, "OK starting build"]
    else
      if newpackage
        return [400, "can't build unless issue is open and has the '#{CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]}'
                      label, or is closed and has the '#{CoreConfig.labels[:TESTING_LABEL]}' label."]
      end
      return [200, "OK not building existing package"]
    end
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

      comment= "Please remember to push to git.bioconductor.org to trigger a new build"

      Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)

      return [400,"Tried to build from github"]
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

  def Core.get_repo_name(repos_url)
    url = "https://api.github.com/repos/"+repos_url
    response = HTTParty.get(url)
    return response.parsed_response["full_name"]
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

  def Core.handle_caps_check_failed(repos_url, github_repo_name, issue_number, login, close=true)
    comment = <<-END.unindent
      Dear @#{login} ,

      The github link provided https://github.com/#{repos_url} ,
      does not match the capitalization of the github repository:
      #{github_repo_name}.
      Please update the link for the repository on this issue page.
    END
    if close
      comment += "I am closing this issue. Please try again with a new issue."
      Core.close_issue(issue_number)
    end
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return "repo capitalization does not match"
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

  def Core.handle_bad_version_number(package_ver, issue_number, login)
    comment = <<-END.unindent
      Dear @#{login},

      The package version number, '#{package_ver}', is not formatted
      correctly. Expecting format: 'x.99.z'.

      Please fix your version number. See [Bioconductor version numbers][1]
      Please also remember to run [BiocCheck::BiocCheck('new-package'=TRUE)][2] on your package
      before submitting a new issue. BiocCheck will look for other
      Bioconductor package requirements.

      [1]: http://contributions.bioconductor.org/description.html#description-ver
      [2]: https://bioconductor.org/packages/BiocCheck/

    END
    Core.close_issue(issue_number)
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return "Invalid Version Number!"
  end

  def Core.handle_x_version_number(package_ver, issue_number, login)
    comment = <<-END.unindent
      Dear @#{login},

      The package version number, '#{package_ver}', does not start
      with 0. Expecting format: '0.99.z' for new packages. Starting
      with non-zero x of 'x.y.z' format is generally only allowed if
      the package has been pre-released.

      We recommend fixing the version number. See [Bioconductor version numbers][1]
      Please also consider running [BiocCheck::BiocCheck('new-package'=TRUE)][2] on your package
      to look for other Bioconductor package requirements.


      [1]: http://contributions.bioconductor.org/description.html#description-ver
      [2]: https://bioconductor.org/packages/BiocCheck/

    END
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return "x of version number non-zero."
  end

  def Core.check_biocviews(description, issue_number, login)
    parser = DebianControlParser.new(description)
    desc_hash = Hash.new
    parser.fields do |name,value|
      desc_hash["#{name}"] = "#{value}".gsub(/\s+/,"")
    end
    ## check if biocViews in DESCRIPTION
    if !desc_hash.keys.include? "biocViews"
      return Core.handle_no_biocviews(issue_number, login)
    end
    views = desc_hash["biocViews"]
    ## check if biocViews has any terms
    if views.nil?
      return Core.handle_no_biocviews(issue_number, login)
    end
    views = views.split(/\s*,\s*/)
    ## check if only top level trivial view
    topLevelViews = ["Software", "AnnotationData", "ExperimentData", "Workflow"]
    if (views - topLevelViews).empty?
      return Core.handle_no_biocviews(issue_number, login)
    end

    tempDir = Dir.tmpdir
    call = "git archive --remote=ssh://git@git.bioconductor.org/packages/biocViews master inst/extdata/biocViewsVocab.sqlite | tar -x --strip=2 -C #{tempDir}"
    system(call)
    dbfileViews = "#{tempDir}/biocViewsVocab.sqlite"
    dbv = SQLite3::Database.new(dbfileViews)
    rows = dbv.execute("select * from biocViews")
    g = RGL::DirectedAdjacencyGraph.new()
    sort_order = []
    for row in rows
      g.add_edge(row.first, row.last)
      sort_order.push row.first
    end

    ## invalids -- message but not show stopper
    ## need to filter invalids to find one category
    ## get value but message after issue closing problems
    ## don't close issue
    bad_view = []
    for bioc_view in views
      if !g.has_vertex? bioc_view
        bad_view.push bioc_view
      end
    end

    ## from one top level category
    grev = g.reverse
    views_filtered = (views - bad_view).uniq
    parents = []
    for bioc_view in views_filtered
      paths = grev.bfs_search_tree_from(bioc_view).vertices
      parents.concat  (paths & topLevelViews)
    end
    if (parents.uniq.length > 1)
      return Core.handle_multiple_category_biocviews(parents.uniq, issue_number, login)
    end

    ## check for duplicates
    duplicates = views.find_all{ |e| views.count(e) > 1}.uniq

    ## message if duplicates or invalid entries
    ## don't close issue
    if ((!duplicates.empty?) || (!bad_view.empty?))
      return Core.handle_formating_biocviews(duplicates, bad_view, issue_number, login)
    end

    return [200, "biocviews okay"]
  end


  def Core.handle_formating_biocviews(duplicates, bad_view, issue_number, login)
    comment = <<-END.unindent
      Dear @#{login},

      The package DESCRIPTION must contain valid biocViews.

    END

    if !duplicates.empty?
      dup = duplicates.join(", ")
      comment = <<-END.unindent
        #{comment}

        The following duplicate terms were found:
        #{dup}

      END
    end

    if !bad_view.empty?
      invalid_term = bad_view.join(", ")
      comment = <<-END.unindent
        #{comment}

        The following are not valid biocViews terms and should be removed
        #{invalid_term}
        If you would like to request a term be added please email the
        bioc-devel@r-project.org mailing list and provide details on
        why and where in the hierarchy you think it should be added.

      END
    end

    comment = <<-END.unindent
      #{comment}

      Please fix your DESCRIPTION. See [current biocViews][1]
      Please also remember to run [BiocCheck::BiocCheck('new-package'=TRUE)][2] on your package
      before submitting a new issue. BiocCheck will look for other
      Bioconductor package requirements.

      [1]: https://bioconductor.org/packages/devel/BiocViews.html
      [2]: https://bioconductor.org/packages/BiocCheck/

    END
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return [200, "formatting of biocViews not okay"]
  end

  def Core.handle_multiple_category_biocviews(toplevelused, issue_number, login)
    termsused = toplevelused.join(", ")
    comment = <<-END.unindent
      Dear @#{login},

      The package DESCRIPTION must contain a biocViews field containing terms
      from only one top level category. Terms from the following were used:
      #{termsused}

      Please fix your DESCRIPTION. See [current biocViews][1]
      Please also remember to run [BiocCheck::BiocCheck('new-package'=TRUE)][2] on your package
      before submitting a new issue. BiocCheck will look for other
      Bioconductor package requirements.

      [1]: https://bioconductor.org/packages/devel/BiocViews.html
      [2]: https://bioconductor.org/packages/BiocCheck/

    END
    Core.close_issue(issue_number)
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return [400, "Multiple level biocViews!"]
  end

  def Core.handle_no_biocviews(issue_number, login)
    comment = <<-END.unindent
      Dear @#{login},

      The package DESCRIPTION must contain a biocViews field with one or more
      valid non-trivial biocViews terms.

      Please fix your DESCRIPTION. See [current biocViews][1]
      Please also remember to run [BiocCheck::BiocCheck('new-package'=TRUE)][2] on your package
      before submitting a new issue. BiocCheck will look for other
      Bioconductor package requirements.

      [1]: https://bioconductor.org/packages/devel/BiocViews.html
      [2]: https://bioconductor.org/packages/BiocCheck/

    END
    Core.close_issue(issue_number)
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return [400, "No biocViews!"]
  end

  def Core.check_file_size(repos_url)
    repos_url = repos_url.sub(/\.git$/, "")
    repos = Octokit.repository(repos_url)
    default_branch = repos['default_branch']
    tree = Octokit.tree(repos_url, "#{default_branch}", :recursive=>true)
    rep_tree = tree[:tree]
    big_files = Array.new
    rep_tree.each{ |x|
      if x[:type] == "blob"
        if x[:size] >= 5000000
          big_files.push(x[:path])
        end
      end
    }
    return big_files
  end

  def Core.handle_big_files_found(big_files, issue_number, login)
    files_text = big_files.join('<br>')
    comment = <<-END.unindent
      Dear @#{login},

      The package contains individual files over 5Mb in size. This is currently
      not allowed. Please remove the following from your repository:

      #{files_text}

      If these are data files we suggest you look at [AnnotationHub][1] or
      [ExperimentHub][2]. Alternatively, it is often possible to illustrate
      package functionality with a smaller, subset of data.

      When the files are removed it will be important to clean your git
      history of the large files. Please see the following instructions:
      [Cleaning large files from git][3]

      I am closing this issue. Please try again with a new issue when resolved.

      [1]: https://bioconductor.org/packages/AnnotationHub/
      [2]: https://bioconductor.org/packages/ExperimentHub/
      [3]: http://contributions.bioconductor.org/git-version-control.html#remove-large-data-files-and-clean-git-tree
    END
    Core.close_issue(issue_number)
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return "Files over 5Mb present!"
  end

  def Core.handle_no_ssh_keys(repos_url, package_name, issue_number,
        login, close=true)
    repos_package_name = repos_url.split('/').last
    comment = <<-END.unindent
      Dear @#{login},

      **Add SSH keys** to your GitHub account. SSH keys will are used
      to control access to accepted _Bioconductor_ packages. See
      [these instructions][1] to add SSH keys to your GitHub
      account. Once you add your SSH keys to your github account,
      please resubmit your issue. We **require** SSH keys to be
      associated with the github username @#{login}.

      [1]: https://help.github.com/articles/adding-a-new-ssh-key-to-your-github-account/
    END
    if close
      comment += "I am closing this issue. Please try again with a new issue."
      Core.close_issue(issue_number)
    end
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    return "No SSH keys for username!"
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

  def Core.handle_preapproval_additional_package(repos, issue_number, password)
    recipient_email = CoreConfig.auth_config["email_recipient"]
    recipient_name = CoreConfig.auth_config["email_recipient_name"]
    from_email = "bioc-github-noreply@bioconductor.org"
    from_name = "Bioconductor Issue Tracker"
    issue = Octokit.issue(Core::NEW_ISSUE_REPO, issue_number)
    Octokit.add_labels_to_an_issue(Core::NEW_ISSUE_REPO, issue_number,
      [CoreConfig.labels[:AWAITING_MODERATION_LABEL]])
    msg = <<-END.unindent
      Hi devteam,

      ADDITIONAL PACKAGE SUBMISSION!

      Repository: https://github.com/#{repos}

      Issue:  https://github.com/#{Core::NEW_ISSUE_REPO}/issues/#{issue_number}

      Approve: #{CoreConfig.request_uri}/moderate_additional_package/#{repos}/#{issue_number}/approve/#{password}

      Reject: #{CoreConfig.request_uri}/moderate_additional_package/#{repos}/#{issue_number}/reject/#{password}

      A github repository has been submitted as an ADDITIONAL PACKAGE to the
      tracker.  I'd like you to take a quick look at it.

      Make sure that

      1. It looks like a package that is intended for _Bioconductor_,
         and not one that is trying to use the single package builder
         for free; and

      2. It does not seem like a malicious package that will try to
         cause damage to our build system. Don't check exhaustively
         for this because there are many ways to hide badness.

      3. The package will need to be added to git.bioconductor.org

      Please approve or reject the package.

      Only one person needs to do this. The web page will tell you if
      it has been done already.

      Please don't reply to this email.

      Thanks,

      The Bioconductor/GitHub issue tracker.
    END
    Core.send_email("#{from_name} <#{from_email}>",
      "#{recipient_name} <#{recipient_email}>",
      "Action required: Please allow/reject ADDITIONAL PACKAGE submitted (issue ##{issue_number}: #{issue[:title]})",
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
      unless (repos_url.split("/").last == package_name) or (package_name == "BioThingsClient") # special case!
        return Core.handle_package_name_mismatch(repos_url, package_name, issue_number, login)
      end
      package_ver = description.scan(/^Version: *(.+)/).first.first.strip
      if !(Core::PKG_VER_REGEX.match(package_ver))
        return Core.handle_bad_version_number(package_ver, issue_number, login)
      end
      if !(Core::PKG_VER_X_REGEX.match(package_ver))
        vl_msg = Core.handle_x_version_number(package_ver, issue_number, login)
      end
      bioc_views_res = Core.check_biocviews(description, issue_number, login)
      if (bioc_views_res[0] != 200)
        return bioc_views_res
      end      
      big_files = Core.check_file_size(repos_url)
      if big_files.length > 0
        return Core.handle_big_files_found(big_files, issue_number, login)
      end

      # Don't count repos keys, instead count login.keys
      # n_ssh_keys = Core.count_ssh_keys(full_repos_url)
      n_ssh_keys = Core.count_login_keys(login)

      if (n_ssh_keys == 0)
        return Core.handle_no_ssh_keys(repos_url, package_name,
                                       issue_number, login, close=true)
      end

      # looking good so far....
      # FIXME - also make sure it's not a repos in Bioconductor-mirror
      # or another one that we definitely know about referring
      # to a package that has already been accepted.

      existing_issue_number = Core.get_repo_issue_number(repos_url)
      if not existing_issue_number.nil?
        return Core.handle_existing_issue(existing_issue_number, issue_number, login)
      end
      pkgname = repos_url.partition('/').last
      existing_issue_number2 = Core.get_repo_issue_number_git(pkgname)
      if not existing_issue_number2.nil?
        return Core.handle_existing_issue2(existing_issue_number, issue_number, login)
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
        # if (n_ssh_keys == 0)
        #   add_keys_comment= <<-END

        #     **Add SSH keys** to your GitHub account. SSH keys
        #     will are used to control access to accepted _Bioconductor_
        #     packages. See [these instructions][1] to add SSH keys to
        #     your GitHub account.

        #     [1]: https://help.github.com/articles/adding-a-new-ssh-key-to-your-github-account/

        #   END
        #   comment += add_keys_comment
        # end
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

          **IMPORTANT**: Please read [this documentation][1] for setting
          up remotes to push to git.bioconductor.org. It is required to push a
          version bump to git.bioconductor.org to trigger a new build.

          Bioconductor utilized your github ssh-keys for git.bioconductor.org
          access. To manage keys and future access you may want to active your
          [Bioconductor Git Credentials Account][2]


          The DESCRIPTION file of your package is:

          ```
          #{description}
          ```
          [1]: http://contributions.bioconductor.org/git-version-control.html#new-package-workflow
          [2]: https://git.bioconductor.org/BiocCredentials
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

  def Core.handle_reopened_issue(obj)
    login = obj['issue']['user']['login']
    body = obj['issue']['body']
    issue_number = obj['issue']['number']
    issue = Octokit.issue(Core::NEW_ISSUE_REPO, issue_number)
    title = issue['title']
    if title.start_with? "(inactive) "
      newtitle = title.gsub("(inactive) ", "")
      Octokit.update_issue(Core::NEW_ISSUE_REPO, issue_number, newtitle, issue['body'])
    end
    labels = Octokit.labels_for_issue(Core::NEW_ISSUE_REPO, issue_number).
               map{|i| i.name}
    if labels.include? CoreConfig.labels[:INACTIVE_LABEL]
      Octokit.remove_label(
        CoreConfig.auth_config['issue_repo'], issue_number,
        CoreConfig.labels[:INACTIVE_LABEL])
    end
    unless labels.include?  CoreConfig.labels[:AWAITING_MODERATION_LABEL]
      if not labels.include?  CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]
        Octokit.add_labels_to_an_issue(
              CoreConfig.auth_config['issue_repo'], issue_number,
              [CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]])
      end
      comment = <<-END.unindent
        Dear @#{login} ,

        We have reopened the issue to continue the review process.
        Please remember to push a version bump to git.bioconductor.org
        to trigger a new build.
      END
      Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    end
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
    # ruby does not allow setting environment variables so use a file
    # cannot check last issue in issue queue for last assigned
    # because package pre-check review is resulting in skipped and unordered
    # assignments
    last_issue_assignee = File.read("lastassignee.txt").split[0]
    # just in case this issue has already been assigned, don't change the assignee:
    this_issue = issues.find{|i| i[:number] == issue_number}
    if (!this_issue.nil?) and (!this_issue[:assignee].nil?)
      return nil # signal the caller not to change assignee
    end

    # filter for temporary no assign
    removeMemList = YAML::load_file(File.join(File.dirname(__FILE__),"excludeAssignmement.yml"))
    if removeMemList
      removeMem = removeMemList.keys
      logins = logins - removeMem
    end
    memhash = {}
    logins.each_with_index do |login, i|
      memhash[login] = i
    end
    last_issue_index = memhash[last_issue_assignee]
    new_assignee = nil
    if last_issue_index.nil? || last_issue_index == (logins.length() -1)
      new_assignee = logins.first
    else
      new_assignee = logins[last_issue_index + 1]
    end
    File.write("lastassignee.txt", new_assignee, mode: "w")
    return new_assignee
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
        A reviewer has been assigned to your package. Learn [what to expect][2]
        during the review process.

        **IMPORTANT**: Please read [this documentation][1] for setting
        up remotes to push to git.bioconductor.org. It is required to push a
        version bump to git.bioconductor.org to trigger a new build.

        Bioconductor utilized your github ssh-keys for git.bioconductor.org
        access. To manage keys and future access you may want to active your
        [Bioconductor Git Credentials Account][3]

        [1]: http://contributions.bioconductor.org/git-version-control.html#new-package-workflow
        [2]: https://github.com/Bioconductor/Contributions#what-to-expect
        [3]: https://git.bioconductor.org/BiocCredentials
      END
      Octokit.add_comment(CoreConfig.auth_config['issue_repo'], issue_number,
        comment)

      labels = Octokit.labels_for_issue(Core::NEW_ISSUE_REPO, issue_number).
        map{|i| i.name}

      if labels.include? CoreConfig.labels[:AWAITING_MODERATION_LABEL]
        Octokit.remove_label(CoreConfig.auth_config['issue_repo'],
                             issue_number, CoreConfig.labels[:AWAITING_MODERATION_LABEL])
      end
      if labels.include? CoreConfig.labels[:PREAPPROVED]
        Octokit.remove_label(CoreConfig.auth_config['issue_repo'],
                             issue_number, CoreConfig.labels[:PREAPPROVED])
      end
      if labels.include? CoreConfig.labels[:PENDING_CHANGES]
        Octokit.remove_label(CoreConfig.auth_config['issue_repo'],
                             issue_number, CoreConfig.labels[:PENDING_CHANGES])
      end
      if labels.include? CoreConfig.labels[:NEED_INTEROP]
        Octokit.remove_label(CoreConfig.auth_config['issue_repo'],
                             issue_number, CoreConfig.labels[:NEED_INTEROP])
      end
      Octokit.add_labels_to_an_issue(CoreConfig.auth_config['issue_repo'],
        issue_number, [CoreConfig.labels[:REVIEW_IN_PROGRESS_LABEL]])

      segs = repos['name'].split("/")
      pkgname = segs.last
      giturl = "https://git.bioconductor.org/packages/" + pkgname

      assignee = Core.get_issue_assignee(issue_number)
      unless assignee.nil?
        Octokit.update_issue(Core::NEW_ISSUE_REPO, issue_number, assignee: assignee)
      end
      Core.start_build(giturl, issue_number, commit_id=nil, newpackage=true)
      return "ok, marked issue as 'ok_to_build', starting a build..."
    end
    return "ok so far"

  end

  def Core.moderate_additional_package(repos1,repos2, issue_number, action, password)
    repos_name = "#{repos1}/#{repos2}"
    unless Core.is_authenticated?
      return "oops, there's a problem with GitHub authentication!"
    end
    repos = Core.get_repo_by_repo_name(repos_name)
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

    if action == "reject"
      comment= <<-END.unindent
        This issue was deemed inappropriate for our issue tracker by a
        member of the Bioconductor team.

        This issue tracker is intended only for packages which are
        being submitted for consideration by Bioconductor.

        Any other use of the tracker is not approved.  If you feel
        this designation is in error, please [send us email][1] and
        include the URL of this issue.

        [1]: maintainer@bioconductor.org
      END
      Octokit.add_comment(CoreConfig.auth_config['issue_repo'], issue_number,
        comment)
      return "ok, additional package rejected."
    else
      comment= <<-END.unindent
        Additional Package has been approved for building.

        **IMPORTANT**: Please read [this documentation][1] for setting
        up remotes to push to git.bioconductor.org. It is required to push a
        version bump to git.bioconductor.org to trigger a new build.

        [1]: http://contributions.bioconductor.org/git-version-control.html#new-package-workflow
      END
      Octokit.add_comment(CoreConfig.auth_config['issue_repo'], issue_number,
        comment)

      labels = Octokit.labels_for_issue(Core::NEW_ISSUE_REPO, issue_number).
        map{|i| i.name}

      if labels.include? CoreConfig.labels[:AWAITING_MODERATION_LABEL]
        Octokit.remove_label(CoreConfig.auth_config['issue_repo'],
                             issue_number, CoreConfig.labels[:AWAITING_MODERATION_LABEL])
      end
      if labels.include? CoreConfig.labels[:PREAPPROVED]
        Octokit.remove_label(CoreConfig.auth_config['issue_repo'],
                             issue_number, CoreConfig.labels[:PREAPPROVED])
      end
      if labels.include? CoreConfig.labels[:PENDING_CHANGES]
        Octokit.remove_label(CoreConfig.auth_config['issue_repo'],
                             issue_number, CoreConfig.labels[:PENDING_CHANGES])
      end
      if labels.include? CoreConfig.labels[:NEED_INTEROP]
        Octokit.remove_label(CoreConfig.auth_config['issue_repo'],
                             issue_number, CoreConfig.labels[:NEED_INTEROP])
      end

      segs = repos_name.split("/")
      pkgname = segs.last
      giturl = "https://git.bioconductor.org/packages/" + pkgname
      Core.start_build(giturl, issue_number, commit_id=nil, newpackage=true)
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


  def Core.start_build(repos_url, issue_number=nil, commit_id=nil, newpackage=true)
    segs = repos_url.sub(/\/$|\.git$/, '').split('/')
    format_ok = repos_url.downcase.start_with?("https://github.com") | repos_url.downcase.start_with?("https://git.bioconductor.org")
    repos_url = "https://github.com/" + repos_url unless format_ok

    pkgsrc = "bioconductor"
    if repos_url.downcase.start_with?("https://github.com") or newpackage
      pkgsrc = "github"
    end

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
    # NOTE: when we open to ALL packages also if !newpackage use packagename for
    # accepted packages
    if issue_number.nil?
      issue_number = "#{pkgname}"
    end
    obj['client_id'] = "single_package_builder_#{pkgsrc}:#{issue_number}:#{pkgname}"
    obj['force'] = true
    config_yaml = Core.get_bioc_config_yaml()
    devel_version = config_yaml['single_package_builder']['bioc_version']
    obj['bioc_version'] = devel_version
    obj['r_version'] = config_yaml['single_package_builder']['r_version']
    obj['svn_url'] = repos_url
    obj['repository'] = 'scratch'
    if !commit_id.nil?
      obj['commit_id'] = commit_id
    end
    obj['newpackage'] = newpackage
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
