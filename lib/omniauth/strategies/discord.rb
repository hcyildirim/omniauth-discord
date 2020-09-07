require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Discord < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = 'identify'.freeze

      option :name, 'discord'

      option :client_options,
             site: 'https://discordapp.com/api',
             authorize_url: 'oauth2/authorize',
             token_url: 'oauth2/token'

      option :authorize_options, %i[scope permissions]

      uid { user_info['id'] }

      info do
        {
          name: user_info['username'],
          email: user_info['verified'] ? user_info['email'] : nil,
          image: "https://cdn.discordapp.com/avatars/#{user_info['id']}/#{user_info['avatar']}"
        }
      end

      extra do
        {
          raw_info: {
            user_info: user_info,
            web_hook_info: web_hook_info
          }
        }
      end

      def user_info
        @user_info ||= access_token.get('users/@me').parsed
      end

      def web_hook_info
        return {} unless access_token.params.key? 'webhook'
        access_token.params['webhook']
      end

      def callback_url
        # Discord does not support query parameters
        options[:callback_url] || (full_host + script_name + callback_path)
      end

      def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |option|
            params[option] = request.params[option.to_s] if request.params[option.to_s]
          end

          params[:scope] ||= DEFAULT_SCOPE
        end
      end
    end
  end
end
