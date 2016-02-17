require 'sinatra'
require 'json'
require 'octokit'
require 'yaml'
require 'httparty'

# here, define the repo we care about
# and other stuff.
# this repo must have bioc-issue-bot as a collaborator, and
# must have a hook defined that points to this app and
# pushes (at least) the "Issues" and "Issue comment" events.
set :new_issue_repo, "dtenenba/settings"
auth_config = YAML::load_file(File.join(File.dirname(__FILE__), "auth.yml" ))
# FIXME - SHOULD use OAuth but having issues:
auth_key = auth_config['auth_key']
login = auth_config['login']
password = auth_config['password']

# FIXME - do authentication more often (on requests?) so it doesn't go stale?
Octokit.configure do |c|
  #c.access_token = auth_key
  c.login = login
  c.password = password
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
  json = request.body.read
  obj = JSON.parse json
  if obj['repository']['full_name'] != settings.new_issue_repo
    puts "got a request from #{obj['repository']['full_name']}, not the one we like."
    return "ignoring issue from other repo"
  end
  if obj['action'] == "opened"
    handle_new_issue(obj)
  elsif obj['action'] == "created" # new issue comment was created
    handle_new_comment(obj)
  end
  'you posted something!'
end

def handle_new_comment(obj)
  puts "got a new comment!"
end

def handle_new_issue(obj)
  puts "got a new issue!"
  body = obj['issue']['body']
  regex = %r{https://github.com/[^/]+/[^ /]+}
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
    comment = <<-END.unindent
      Thanks! You submitted a single valid GitHub URL that points to
      an R package (at least it has a DESCRIPTION file).

      Pretend that I have run the single package builder
      on your package and put the results here:

      https://some.invalid.url/that/contains/your/build/results/

      In reality this code is not integrated with the SPB yet so this
      is just a stub.

    END
    Octokit.add_comment(settings.new_issue_repo, issue_number, comment)
  end
  puts "this is the body:\n #{body}"
end
