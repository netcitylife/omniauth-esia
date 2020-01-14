require 'omniauth-oauth2'
require 'base64'

module OmniAuth
  module Strategies
    class Esia < OmniAuth::Strategies::OAuth2

      option :name, 'esia'
      option :client_options, {
        site:          'https://esia.gosuslugi.ru',
        authorize_url: 'aas/oauth2/ac',
        token_url:     'aas/oauth2/te',
      }
      option :scope, 'fullname'
      option :key_path, 'config/keys/private.key'
      option :crt_path, 'config/keys/certificate.crt'
      option :key_file, nil
      option :crt_file, nil
      option :access_type, 'online'

      option :extra_info, []

      uid { JWT.decode(access_token.token, nil, false).first['urn:esia:sbj_id'] }

      info do
        raw_info
      end

      extra do
        data = {}

        options.extra_info.each do |info|
          method = "get_#{info}"
          if respond_to?(method, true)
            data[info] = send(method)
          end
        end

        data
      end

      def authorize_params
        super.tap do |params|
          params[:state]            = state
          params[:timestamp]        = timestamp
          params[:client_secret]    = client_secret
          params[:access_type]      = options.access_type
          session['omniauth.state'] = state
        end
      end

      def client
        ::OAuth2::Client.new(options.client_id, client_secret, deep_symbolize(options.client_options))
      end

      def raw_info
        @raw_info ||= get_resource
      end

      protected

      def build_access_token
        verifier = request.params["code"]
        client.auth_code.get_token(verifier, {
          state:        state,
          scope:        options.scope,
          timestamp:    timestamp,
          redirect_uri: callback_url,
          token_type:   'Bearer'
        })
      end

      private

      def client_secret
        @client_secret ||= begin
          data   = "#{options.scope}#{timestamp}#{options.client_id}#{state}"
          key    = options.key_file || OpenSSL::PKey.read(File.read(options.key_path))
          crt    = options.crt_file || OpenSSL::X509::Certificate.new(File.read(options.crt_path))
          signed = OpenSSL::PKCS7.sign(crt, key, data, [], OpenSSL::PKCS7::DETACHED)
          Base64.urlsafe_encode64(signed.to_der.to_s.force_encoding('utf-8'), padding: false)
        end
      end

      def state
        @state ||= SecureRandom.uuid
      end

      def timestamp
        @timestamp ||= Time.now.strftime('%Y.%m.%d %H:%M:%S %z')
      end

      def get_contacts(ctt_id = nil)
        @get_contacts ||= get_resource('ctts', ctt_id).fetch('elements', [])
      end

      def get_addresses(addr_id = nil)
        @get_addresses ||= get_resource('addrs', addr_id).fetch('elements', [])
      end

      def get_documents(doc_id = nil)
        @get_documents ||= get_resource('docs', doc_id).fetch('elements', [])
      end

      def get_vehicles(vhl_id = nil)
        @get_vehicles ||= get_resource('vhls', vhl_id).fetch('elements', [])
      end

      def get_organizations
        @get_organizations ||= get_resource('roles', nil, false).fetch('elements', [])
      end

      def get_kids(kid_id = nil)
        @get_kids ||= get_resource('kids', kid_id).fetch('elements', [])
      end

      def get_passport
        @get_passport ||= get_documents(raw_info[:rIdDoc])[0]
      end

      def get_resource(collection = nil, entity_id = nil, embed = true)
        resource = ''
        resource += "/#{collection}" if collection
        resource += "/#{entity_id}" if entity_id
        resource += '?embed=(elements)' if embed

        access_token.get("/rs/prns/#{uid}#{resource}").parsed
      end
    end
  end
end

OmniAuth.config.add_camelization 'esia', 'Esia'
