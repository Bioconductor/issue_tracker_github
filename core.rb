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

class String
  # Strip leading whitespace from each line that is the same as the
  # amount of whitespace on the first line of the string.
  # Leaves _additional_ indentation on later lines intact.
  def unindent()
    gsub(/^#{self[/\A[ \t]*/]}/,'')
  end
end

class CoreConfig
  @@request_uri  = nil
  @@db = nil
  @@auth_config = nil
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
  # of in this script. So far they are:
  #  - new-package 'awaiting moderation'
  # Also, build system statuses (with appropriate colors):
  # OK WARNINGS TIMEOUT ERROR abnormal
  # See https://help.github.com/articles/creating-and-editing-labels-for-issues-and-pull-requests/

  CoreConfig.set_auth_config(YAML::load_file(File.join(File.dirname(__FILE__), "auth.yml" )))



  NEW_ISSUE_REPO = CoreConfig.auth_config['issue_repo']
  REQUIRE_PREAPPROVAL = CoreConfig.auth_config['require_preapproval']

  # FIXME - do authentication more often (on requests?) so it doesn't go stale?
  # Not sure yet if this is a problem.

  # A note about OAuth. When setting up the token, it must have
  # the 'public_repo' scope
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
      puts "IP is not from github"
      return "sorry, working through some trust issues with unknown IP addresses."
    end
    json = request.body.read
    obj = JSON.parse json
    if (!obj.has_key?'action') and (!obj.has_key?'ref')
      return 'I can only handle push and issue (and issue comment)event hooks'
    end
    if obj.has_key? 'ref'
      return Core.handle_push(obj)
    end
    if obj.has_key? 'action' and obj['action'] == "created"
      return Core.handle_issue_comment(obj)
    end
    if obj['repository']['full_name'] != Core::NEW_ISSUE_REPO
      puts "got a request from #{obj['repository']['full_name']}, not the one we like."
      return "ignoring issue from other repo"
    end
    # FIXME allow people to continue to build (closed?) issues
    # if they have the label "testing".
    if obj.has_key? 'action' and  obj['action'] == "opened"
      return Core.handle_new_issue(obj)
    end
    'you posted something!'
  end

  def Core.handle_issue_comment(obj)
    # TODO implement
    # issue comments may be used to submit additional packages
    # (such as experiment data packages) to be reviewed together
    # with the main package.
    # Be sure and ignore all comments posted by this bot itself.
    return "handled issue comment"
  end

  # FIXME This checks if our DB already has a rowa with the same repos name.
  # We should also check if GitHub already has a repo with this name.
  def Core.handle_existing_issue(existing_issue_number, issue_number, login)
    comment= <<-END.unindent
      Dear @#{login} ,
      You (or someone) has already posted that repository to our tracker.

      See https://github/#{Core::NEW_ISSUE_REPO}/issues/#{existing_issue_number}

      You cannot post the same repository more than once.

      I am closing this issue.

    END
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    Core.close_issue(issue_number)
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

  def Core.handle_push(obj)
    puts "in handle_push"
    repos = obj['repository']['full_name']
    db_record = get_repo_by_repo_name(repos)
    if db_record.nil?
      return "Sorry, you haven't told us about this repository, please
      go to https://github.com/#{Core::NEW_ISSUE_REPO}/issues/new ."
    end
    issue_number = db_record['issue_number']
    issue = Octokit.issue(Core::NEW_ISSUE_REPO, issue_number)
    build_ok = false
    labels = Octokit.labels_for_issue(Core::NEW_ISSUE_REPO, issue_number).
      map{|i| i.name}
    if issue['state'] = "open" and labels.include? "ok_to_build"
      build_ok = true
    elsif issue['state'] = "closed" and labels.include? "testing"
      build_ok = true
    end
    if build_ok
      Core.start_build(repos, issue_number)
      return "ok, starting build"
    else
      return "can't build unless issue is open and has the 'ok_to_build'
      label, or is closed and has the 'testing' label."
    end
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
      I found more than one GitHub URL in your issue! Please make sure there
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

  def Core.handle_repo_does_not_exist(repos_url, issue_number, login)
    comment = <<-END.unindent
      Dear @#{login} ,

      There is no repository called https://github.com/#{repos_url} .
      You must submit the url to a valid, public GitHub repository.
      I am closing this issue. Please try again with a new issue.
    END
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    Core.close_issue(issue_number)
    return "repos does not exist"
  end

  def Core.has_description_file? (repos_url, obj)
    repos = Octokit.repository(repos_url)
    default_branch = repos['default_branch']
    desc_url = "https://raw.githubusercontent.com/#{repos_url}/#{default_branch}/DESCRIPTION"
    response = HTTParty.get(desc_url)
    return response.code == 200
  end

  def Core.handle_no_description_file(full_repos_url, issue_number, login)
    comment = <<-END.unindent
      Dear @#{login} ,
      I could not find a DESCRIPTION file in the default branch of
      the GitHub repository at
      #{full_repos_url} .
      This repository should contain an R package.

      I am closing this issue. Please try again with a new issue.
    END
    Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
    Core.close_issue(issue_number)
    return "no description file found!"
  end

  def Core.handle_preapproval(repos, issue_number, password)
    recipient_email = CoreConfig.auth_config["email_recipient"]
    recipient_name = CoreConfig.auth_config["email_recipient_name"]
    from_email = "bioc-github-noreply@bioconductor.org"
    from_name = "Bioconductor Issue Tracker"
    issue = Octokit.issue(Core::NEW_ISSUE_REPO, issue_number)
    Octokit.add_labels_to_an_issue(Core::NEW_ISSUE_REPO, issue_number,
      ['awaiting moderation'])
    msg = <<-END.unindent
      Hi devteam,

      Someone submitted a package to the tracker
      with the title '#{issue['title']}'
      (https://github.com/#{Core::NEW_ISSUE_REPO}/issues/#{issue_number})
      and I'd like you to take a quick look at it before we let it into the
      single package builder.

      Just make sure that

      1) it looks like a package that is intended for Bioconductor,
      and not just one that is trying to use the single package builder
      for free; and
      2) It does not seem like a malicious package that will try to
      cause damage to our build system. Don't check exhaustively
      for this because there are many ways to hide badness.

      The package is at the following github repository:

      https://github.com/#{repos}

      If you approve of it, please click the following link:

      #{CoreConfig.request_uri}moderate_new_issue/#{issue_number}/approve/#{password}

      To reject it, click here:

      #{CoreConfig.request_uri}moderate_new_issue/#{issue_number}/reject/#{password}

      Only one person needs to do this. The web page will
      tell you if it has been done already.

      After the package has been
      approved (or rejected) once, the remaining steps will be handled
      automatically.

      The contributor will be told to read the guidelines and try again.
      You can always post a more personalized message by going
      to https://github.com/#{Core::NEW_ISSUE_REPO}/issues/#{issue_number}
      You can then manually allow the package to be built by adding
      the "ok_to_build" label to the issue. To manually reject the
      issue, just close it.

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
    regex = %r{https://github.com/[^/]+/[^ /\s]+}
    match = body.scan(regex)
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
      unless Core.has_description_file?(repos_url, obj)
        return Core.handle_no_description_file(full_repos_url, issue_number, login)
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
      Core.add_repos_to_db(repos_url, hash, issue_number, login)
      if REQUIRE_PREAPPROVAL
        return Core.handle_preapproval(repos_url, issue_number, password)
      else
        comment = <<-END.unindent
          Thanks, @#{login} ! You submitted a single valid GitHub URL that points to
          an R package (at least it has a DESCRIPTION file).

          Your package is now submitted to our queue.

          **IMPORTANT**: Please read
          [the instructions](https://github.com/#{Core::NEW_ISSUE_REPO}/blob/master/CONTRIBUTING.md)
          for setting up a push hook on your repository, or
          further changes to your repository will NOT trigger a new
          build.
        END
        Octokit.add_comment(Core::NEW_ISSUE_REPO, issue_number, comment)
        Octokit.add_labels_to_an_issue(Core::NEW_ISSUE_REPO, issue_number,
        ["new-package", "ok_to_build"])
        Core.start_build(repos_url, issue_number)
      end
    end
    return "handled new issue"
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
    if labels.find {|i| i.name == "ok_to_build"}
      return "this issue has already been marked 'ok_to_build'."
    end
    if action == "reject"
      comment= <<-END.unindent
        This issue was deemed inappropriate for our issue tracker by
        a member of the Bioconductor team.

        This issue tracker is intended only for packages which are being
        submitted for consideration by Bioconductor.

        Any other use of the tracker is not approved.
        If you feel this designation is in error, please
        email maintainer@bioconductor.org and include the URL
        of this issue.

        This issue will now be closed.
      END
      Octokit.add_comment(CoreConfig.auth_config['issue_repo'], issue_number,
        comment)
      Core.close_issue(issue_number, issue)
      return "ok, issue rejected."
    else
      comment= <<-END.unindent
        Your package has been approved for building.
        Your package is now submitted to our queue.

        **IMPORTANT**: Please read
        [the instructions](https://github.com/#{Core::NEW_ISSUE_REPO}/blob/master/CONTRIBUTING.md)
        for setting up a push hook on your repository, or
        further changes to your repository will NOT trigger a new
        build.

      END
      Octokit.add_labels_to_an_issue(CoreConfig.auth_config['issue_repo'],
        issue_number, ["ok_to_build"])
      # FIXME  start a build!
      repos_url = "https://github.com/#{repos['name']}"
      Core.start_build(repos_url, issue_number)
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
    yaml_content = open("http://bioconductor.org/config.yaml"){|f| f.read}
    YAML::load(yaml_content)
  end


  def Core.start_build(repos_url, issue_number)
    segs = repos_url.sub(/\/$|\.git$/, '').split('/')
    repos_url = "https://github.com/" +
      repos_url unless repos_url.downcase.start_with?("https://github.com")
    pkgname = segs.last
    now = Time.now
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
    devel_version = config_yaml['devel_version']
    obj['bioc_version'] = devel_version
    obj['r_version'] = config_yaml['r_ver_for_bioc_ver'][devel_version]
    obj['svn_url'] = repos_url
    obj['repository'] = 'scratch'
    json = obj.to_json

    stomp = CoreConfig.auth_config['stomp']
    stomp_hash = {hosts: [{host: stomp['broker'], port: stomp['port']}]}
    client = Stomp::Client.new(stomp_hash)
    client.publish("/topic/buildjobs", json)
  end


end # end of Core module
