require 'sinatra'
require 'json'
require 'octokit'
require 'yaml'
require 'httparty'
require 'net/smtp'
require 'pry' # remove this when not needed

# here, define the repo we care about
# and other stuff.
# this repo must have bioc-issue-bot as a collaborator, and
# must have a hook defined that points to this app and
# pushes (at least) the "Issues" event.
# After 'registering' their package in our issues repo,
# developers can then set up webhooks to send us push
# notifications.
# Also need to make sure that the repos has whatever
# custom labels (defined on issues) that we make use
# of in this script. So far they are:
#  - new-package
# Also, build system statuses (with appropriate colors):
# OK WARNINGS TIMEOUT ERROR abnormal
# See https://help.github.com/articles/creating-and-editing-labels-for-issues-and-pull-requests/
set :new_issue_repo, "dtenenba/settings"
auth_config = YAML::load_file(File.join(File.dirname(__FILE__), "auth.yml" ))
# A note about OAuth. When setting up the token, it must have
# the 'public_repo' scope
auth_key = auth_config['auth_key']

# FIXME - do authentication more often (on requests?) so it doesn't go stale?
# Not sure yet if this is a problem.
Octokit.configure do |c|
  c.access_token = auth_key
end



class String
  # Strip leading whitespace from each line that is the same as the
  # amount of whitespace on the first line of the string.
  # Leaves _additional_ indentation on later lines intact.
  def unindent
    gsub /^#{self[/\A[ \t]*/]}/, ''
  end
end



get '/' do
  'nothing to see here yet'
end

# FIXME - check for valid github IP or headers to make sure
# we are not getting spoof requests, see
# https://help.github.com/articles/what-ip-addresses-does-github-use-that-i-should-whitelist/#service-hook-ip-addresses
post '/' do
  if is_spoof? request
    puts "IP is not from github"
    return "sorry, working through some trust issues with unknown IP addresses."
  end
  json = request.body.read
  obj = JSON.parse json
  if (!obj.has_key?'action') and (!obj.has_key?'ref')
    return 'I can only handle push and issue event hooks'
  end
  if obj.has_key? 'ref'
    return handle_push(obj)
  end
  if obj['repository']['full_name'] != settings.new_issue_repo
    puts "got a request from #{obj['repository']['full_name']}, not the one we like."
    return "ignoring issue from other repo"
  end
  # FIXME allow people to continue to build (closed?) issues
  # if they have the label "testing".
  if obj.has_key? 'action' and  obj['action'] == "opened"
    return handle_new_issue(obj)
  end
  'you posted something!'
end

def is_spoof? (request)
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
  return false if ip == "127.0.0.1" # allow local testing
  regex = %r{^192\.30\.25[2345]\.}
  ip !~ regex
end

def handle_push(obj)
  puts "in handle_push"
  # FIXME ignore pushes from repos that haven't set up an issue in
  # our new packages repo. (We could post an issue in those repos
  # if we want to make sure the package author sees it.)
  return "handled push"
end

def handle_new_issue(obj)
  puts "got a new issue!"
  body = obj['issue']['body']
  regex = %r{https://github.com/[^/]+/[^ /\s]+}
  match = body.scan(regex)
  issue_number = obj['issue']['number']
  if match.empty?
    comment= <<-END.unindent
      I couldn't find a GitHub repository URL in your issue text!
      Please include a github repository URL, it should look like this:

      https://github.com/username/reponame

      I am closing this issue. Please try again with a new issue.
    END
    Octokit.add_comment(settings.new_issue_repo, issue_number, comment)
    Octokit.close_issue(settings.new_issue_repo, issue_number)
  elsif match.length > 1 # FIXME what if there is supposed to be more than
                         # one package? As in software + data package?
    comment = <<-END.unindent
      I found more than one GitHub URL in your issue! Please make sure there
      is only one, it should look like:

      https://github.com/username/reponame

      I am closing this issue. Please try again with a new issue.
    END
    Octokit.add_comment(settings.new_issue_repo, issue_number, comment)
    Octokit.close_issue(settings.new_issue_repo, issue_number)
  else # there is just one URL
    repos_url = match.first.sub("https://github.com/", "").strip
    begin
      repos = Octokit.repository(repos_url)
    rescue Octokit::NotFound
      comment = <<-END.unindent
        No such repository!
        There is no repository called #{match.first.strip} .
        You must submit the url to a valid, public GitHub repository.
        I am closing this issue. Please try again with a new issue.
      END
      Octokit.add_comment(settings.new_issue_repo, issue_number, comment)
      Octokit.close_issue(settings.new_issue_repo, issue_number)
      return "return from invalid url"
    end
    default_branch = repos['default_branch']
    desc_url = "https://raw.githubusercontent.com/#{repos_url}/#{default_branch}/DESCRIPTION"
    response = HTTParty.get(desc_url)
    unless response.code == 200
      comment = <<-END.unindent
        I could not find a DESCRIPTION file in the default branch of
        the GitHub repository at
        #{match.first.strip} .
        This repository should contain an R package.

        I am closing this issue. Please try again with a new issue.
      END
      Octokit.add_comment(settings.new_issue_repo, issue_number, comment)
      Octokit.close_issue(settings.new_issue_repo, issue_number)
      return "no description file found!"
    end
    # looking good so far....
    # FIXME - make sure issue is not one that we are already tracking
    # (at least in an open issue).
    # FIXME - also make sure it's not a repos in Bioconductor-mirror
    # or another one that we definitely know about referring
    # to a package that has already been accepted.
    require_preapproval = true
    if require_preapproval
      # FIXME change this to devteam-bioc@lists.fhcrc.org in production
      # (from address is configured to be able to send email to devteam):
      recipient_email = "dtenenba@fredhutch.org"
      recipient_name = "Dan Tenenbaum" # also change in prod
      from_email = "bioc-github-noreply@bioconductor.org"
      issue = Octokit.issue(settings.new_issue_repo, issue_number)
      msg = <<-END.unindent
        From: Bioconductor Issue Tracker <#{from_email}>
        To: #{recipient_name} <#{recipient_email}>
        Subject: New package submitted to tracker (issue ##{issue_number}: #{issue[:title]})

        Hi Bioconductors,

        Someone submitted a package to the tracker (https://github.com/#{settings.new_issue_repo}/issues)
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

        #{match.first.strip}

        If you approve of it, please click the following link:

        ...

        To reject it, click here:

        ...

        Only one person needs to do this. After the package has been
        approved (or rejected) once, the remaining steps will be handled
        automatically.

        The contributor will be told to read the guidelines and try again.
        You can always post a more personalized message by going
        to https://github.com/#{settings.new_issue_repo}/issues/#{issue_number}
        (instead of clicking the reject link above).
        Type a message and then click "Close Issue".

        Please don't reply to this email.
      END
      mail = auth_config['mail']
      smtp = Net::SMTP.new(mail['server'], mail['port'])
      smtp.enable_starttls if mail['tls']
      smtp.start('localhost', mail['username'], mail['password'])
      smtp.send_message(msg, from_email, recipient_email)

    else
      comment = <<-END.unindent
        Thanks! You submitted a single valid GitHub URL that points to
        an R package (at least it has a DESCRIPTION file).

        Your package is now submitted to our queue.

        FIXME - add more info here about how to
        add a push hook to your repos to build on subsequent
        pushes....
      END
      Octokit.add_comment(settings.new_issue_repo, issue_number, comment)
      Octokit.add_labels_to_an_issue(settings.new_issue_repo, issue_number, ["new-package"])
    end
  end
  puts "this is the body:\n #{body}"
  return "handled new issue"
end
