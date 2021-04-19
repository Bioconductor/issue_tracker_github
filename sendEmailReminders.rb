#!/usr/bin/env ruby
if ARGV.length < 1
  adminflag = false
else
  adminflag = ARGV[0]
end


require 'octokit'
require 'yaml'
require 'aws-sdk'

auth_config = YAML::load_file(File.join(File.dirname(__FILE__), "auth.yml" ))

Octokit.auto_paginate = true
GITHUB = Octokit::Client.new(access_token: auth_config['auth_key'])


class String
  def unindent()
    gsub(/^#{self[/\A[ \t]*/]}/,'')
  end
end

def send_email(from, to, subject, message)
  auth_config = YAML::load_file(File.join(File.dirname(__FILE__), "auth.yml" ))
  aws = auth_config['aws']
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
                       }
                     },
                   }
                 })
end


revEmails = YAML::load_file(File.join(File.dirname(__FILE__), "ReviewerEmails.yml"))

teams = GITHUB.organization_teams("Bioconductor")
## requires later version of octokit
## pkgRevTeam = GITHUB.team_by_name("Bioconductor", "PackageReviewers")
## reviewers = GITHUB.team_members(pkgRevTeam[:id])
##
team_number = auth_config["reviewer_team_number"]
reviewers = GITHUB.team_members(team_number)

admin_name = "Lori Shepherd"
admin_email = "lori.shepherd@roswellpark.org"

admin_file_name = "adminEmail.txt"
File.open(admin_file_name, "w")
admin_body = <<-END.unindent
         Hello #{admin_name}   

         Here is this weeks overview of reviewers and packages:




END
File.write(admin_file_name, admin_body, mode: "a")


reviewers.each{ |rev|
  ##puts  rev[:login]
  github_name = rev[:login]
  if revEmails["#{github_name}"].nil?
    File.write(admin_file_name, "REVIEWER:  #{github_name} :  ERROR!! Github reviewer not added to email yaml.\n\n\n", mode: "a")
  else
    file_name = "#{github_name}.txt"
    emailTo = revEmails["#{github_name}"]["email"]
    fullName =  revEmails["#{github_name}"]["name"]
    File.write(admin_file_name, "REVIEWER:  #{github_name} : #{fullName} : #{emailTo}\n", mode: "a")
    File.open(file_name, "w")
    msg =  <<-END.unindent
      Hello #{fullName}
      
      Thank you for committing to be a Bioconductor package reviewer.

      Please find a brief overview of the packages you are currently assigned for
      review. Remember any package that is awaiting responses from you should be
      addressed within 21 days.

      We appreciate your continued efforts to Bioconductor and helping new and
      existing contributors publish packages in Bioconductor.





 
    END
    File.write(file_name, msg, mode: "a")
    issue = GITHUB.list_issues(auth_config['issue_repo'], state: 'open', labels: "2. review in progress", assignee: rev[:login])
    totNum = issue.length
    File.write(file_name, "Total Number of Issues Currently Reviewing: #{totNum}\n\n\n", mode: "a")
    issue.each{ | iss |
      title=iss[:title]
      num = iss[:number]
      issue_url = iss[:html_url]
      File.write(file_name, "  #{num} : #{title}\n", mode: "a")
      submitter = iss[:user][:login]
      comments = GITHUB.issue_comments(auth_config['issue_repo'],iss[:number])
      last = comments.last
      days = ((Time.now - last[:created_at])/(24 * 60 * 60)).round
      user = last[:user][:login]
      body = last[:body][1..100].delete("\t\r\n")
      labels = GITHUB.labels_for_issue(auth_config['issue_repo'],iss[:number])
      res = []
      labels.each{ |lab|
        if ['OK', 'WARNINGS', 'ERROR', 'ABNORMAL'].include? lab[:name]
          res.push(lab[:name])
        end
      }
      status = res.join(', ')
      addpkg = false
      comments.each{ | com |
        if com[:body].include? "AdditionalPackage"
          addpkg = true
        end
      }
      File.write(file_name, "      Issue URL: #{issue_url}\n", mode: "a")
      File.write(file_name, "      Submitted by: #{submitter}\n", mode: "a")
      if addpkg
        File.write(file_name, "      AddtionalPackage: TRUE\n", mode: "a")
      end
      File.write(file_name, "      Days Since Last comment: #{days}\n", mode: "a")
      File.write(file_name, "      Last comment made by: #{user}\n", mode: "a")
      File.write(file_name, "      Build/Check status: #{status}\n", mode: "a")
      File.write(file_name, "      Last comment body: #{body}\n\n\n", mode: "a")       
    }
    msg_body = File.read(file_name)
    from_email = "bioc-github-noreply@bioconductor.org"
    from_name = "Bioconductor Package Review Submission Tracker"
    send_email("#{from_name} <#{from_email}>", "#{fullName} <#{emailTo}>",
               "Bioconductor Package Review Reminder", msg_body)
    msg_body.slice! msg
    File.write(admin_file_name,msg_body, mode: "a")
    File.delete(file_name)
  end
  File.write(admin_file_name,"\n\n\n\n", mode: "a")
}

msg_body_admin = File.read(admin_file_name)
from_email = "bioc-github-noreply@bioconductor.org"
from_name = "Bioconductor Package Review Submission Tracker"
if adminflag.eql? "true"
  send_email("#{from_name} <#{from_email}>", "#{admin_name} <#{admin_email}>",
             "Bioconductor Package Reviewer Overview", msg_body_admin)
end
File.delete(admin_file_name)
