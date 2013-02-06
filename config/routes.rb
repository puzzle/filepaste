Filepaste::Application.routes.draw do

  namespace :admin do
    resources :uploads
  end

  resources :uploads

  root to: 'uploads#new'
  
  match ':controller/:action/:id'
  match ':controller/:action/:id.:format'

end
