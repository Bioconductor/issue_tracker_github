require 'sinatra'
require_relative './core'
require 'pry' # remove when not needed

get '/' do
  'Nothing to see here'
end

post '/' do
  return Core.handle_post(request)
end

get '/start_build/:pkgname/:commitid' do
  return Core.handle_git_push_newpackage(params[:pkgname], params[:commitid])
end

get '/moderate_new_issue/:issue/:action/:password' do
  return Core.moderate_new_issue(params[:issue], params[:action],
    params[:password])
end
