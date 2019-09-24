# issue\_tracker\_github

This is server-side software for managing new package issues submitted
to the 'Contribution' Bioconductor github repository.

## Setup

The software runs on an Amazon nano-instance at
issues.bioconductor.org, accessible via ssh.

Setup is via a [chef][] recipe. Update the recipe by commiting to the
github repository, then `berks install`. On the
issues.bioconductor.org

    sudo su - www-data
    chef-client

## Work flow

The software notifies the [single package builder][] of the repository
to retrieve the package from, and the package is build across Linux,
Mac, and Windows.

## Debugging

- issues.bioconductor.org
- checkip.amazonaws.com
- EC2 Management Console
  - NETWORK & SECURITY
  - ssh; edit inbound rules
- ssh ubuntu@issues.bioconductor.org
  sudo su - www-data

The software is running under apache. Error and access logs are at
`/var/log/apache2` as ubuntu.

Use `pry` for interactive ruby. Ensure that the approporiate pry is
available (via `rbenv`)

    $ which pry
    /var/www/.rbenv/shims/rpy
    
start `pry` (from the home directory of www-data) and require the core
application

    $ pry
    [1] pry(main)> require_relative './app/core'
    => true
    [2] pry(main)> 

## Updating

Make changes in personal clone of git repository, push to
github.com/Bioconductor/issue_tracker_github.

On ubuntu@issues.bioconductor.org

    sudo chef-client


### Updating data bags

There are authentication credentials encoded by [chef data bags][]. 
See git credentials for keys to authorize changes. 
To show contains of a data bag:

     knife data bag show IssueTrackerConfig IssueTrackerConfig --secret-file /home/lori/Documents/databag.key

To edit the contents of the data bag: 

    knife data bag edit IssueTrackerConfig IssueTrackerConfig --secret-file /home/lori/Documents/databag.key 
    
The data bag should remain encrypted but to test run the show command without including --secret-file 
and it should show encrypted contents. 

You can list all managed data bags by doing 

    knife data bag list
    
The aws keys correspond to the sdk-email user security credentials.


[chef]: https://github.com/Bioconductor/issue_tracker_github_cookbook
[single package builder]: https://staging.bioconductor.org:8000.
[chef data bags]: https://docs.chef.io/knife_data_bag.html
