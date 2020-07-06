require 'sinatra'
require_relative './core'
require 'pry' # remove when not needed

get '/' do
  'Nothing to see here'
end

post '/' do
  return Core.handle_post(request)
end

post '/start_build' do
  return Core.handle_git_push(request)
end

get '/moderate_new_issue/:issue/:action/:password' do
  return Core.moderate_new_issue(params[:issue], params[:action],
    params[:password])
end

get '/moderate_additional_package/:repos1/:repos2/:issue/:action/:password' do
  return Core.moderate_additional_package(params[:repos1], params[:repos2], params[:issue],
  params[:action], params[:password])
end
