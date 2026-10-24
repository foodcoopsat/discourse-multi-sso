# name: discourse-multi-sso
# about: Multiple Discourse SSO Plugin
# version: 0.1
# authors: Patrick Gansterer
# url: https://github.com/paroga/discourse-multi-sso

$LOAD_PATH.unshift File.expand_path("vendor/omniauth-discourse/lib", __dir__)
require "omniauth-discourse"

require_dependency 'auth/authenticator.rb'

register_asset 'stylesheets/common/multi_sso.scss'

enabled_site_setting :multi_sso_enabled

# route: /admin/plugins/explorer
#add_admin_route 'multi_sso.title', 'multi_sso'

class ::OmniAuth::Strategies::MultiSso < ::OmniAuth::Strategies::Discourse

  alias original_request_phase request_phase

  option :config_id

  # OmniAuth 2 builds callback_url from the *current* query string. The selection
  # form POSTs `id` in the body, so it would be lost and the callback could not
  # tell which config (and thus which sso_secret) to verify against. Carry it
  # explicitly; the provider appends sso/sig to this URL.
  def callback_url
    return super unless options.config_id
    "#{full_host}#{callback_path}?id=#{CGI.escape(options.config_id.to_s)}"
  end

  def request_phase
    # setup already resolved a config from the `id` param
    return original_request_phase if options.config_id

    # Discourse only allows POST on /auth/:provider and verifies the CSRF token
    # in before_request_phase, so the selection forms need a token too. The
    # current request already passed that check, so call() won't raise here.
    verifier = CSRFTokenVerifier.new
    verifier.call(env)
    csrf_token = Rack::Utils.escape_html(verifier.form_authenticity_token)

    title = SiteSetting.multi_sso_select_title
    text = SiteSetting.multi_sso_select_text

    html = <<-HTML
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <title>#{title}</title>
  <script>window.resizeTo(640,800)</script>
  <style>
    form { display: inline; }
    button { background: none; border: none; padding: 0; font: inherit; cursor: pointer; text-align: left; }
    button:hover { text-decoration: underline; }
  </style>
</head>
<body style="font-family: sans-serif">
  <h1>#{title}</h1>
  <p>#{text}</p>
  <ul>
HTML

    PluginStoreRow.where(plugin_name: MultiSso.plugin_name)
      .where("key LIKE 'c:%'")
      .order(:key)
      .each do |psr|
      id = psr.key[2..-1]
      config = PluginStore.cast_value(psr.type_name, psr.value)
      if config[:list]
        html << "<li>"
        html << "<form action=\"#{request_path}\" method=\"post\">"
        html << "<input type=\"hidden\" name=\"authenticity_token\" value=\"#{csrf_token}\">"
        html << "<input type=\"hidden\" name=\"id\" value=\"#{id}\">"
        html << "<button type=\"submit\">#{config[:name]}</button>"
        html << "</form>"
        html << "</li>"
      end
    end

    html << <<-HTML
  </ul>
</body>
</html>
HTML

    Rack::Response.new(html, 200, 'content-type' => 'text/html').finish
  end

  extra do
    {
      config_id: options.config_id,
      require_activation: user_info[:require_activation]
    }
  end
end

module ::MultiSso

  class Authenticator < ::Auth::ManagedAuthenticator
    def name
      'multi_sso'
    end

    def enabled?
      SiteSetting.multi_sso_enabled
    end

    def register_middleware(omniauth)
      omniauth.provider :multi_sso,
                        name: 'multi_sso',
                        setup: lambda { |env|
                          opts = env['omniauth.strategy'].options
                          # GET query + POST form body (selection form, callback ?id=)
                          params = Rack::Request.new(env).params
                          config_id = params['id'].presence

                          if config_id && config = MultiSso.pstore_get("c:#{config_id}")
                            opts[:config_id] = config_id
                            opts[:sso_url] = config[:sso_url]
                            opts[:sso_secret] = config[:sso_secret]
                          end

                          # Legacy ?destination_url=: Discourse core now owns the
                          # redirect target and reads it from omniauth.origin.
                          if (dest = params['destination_url'].presence)
                            env['rack.session']['omniauth.origin'] = dest
                          end
                        }
    end

    def description_for_auth_hash(auth_token)
      auth_token&.provider_uid
    end

    def match_by_email
      false
    end

    def can_connect_existing_user?
      false
    end

    def after_authenticate(auth_token)
      external_id = auth_token[:uid]
      data = auth_token[:info]
      extra = auth_token[:extra]

      config_id = extra[:config_id]
      config = MultiSso.pstore_get("c:#{config_id}")

      auth_token[:provider] = "#{name}:#{config_id}"
      result = super(auth_token)
      result.email_valid = config[:trust_email] && !extra[:require_activation]

      require_activation = config[:require_activation] || config[:trust_email] && extra[:require_activation]

      user = result.user
      if !user
        user = User.find_by_email(result.email)
        if !user
          begin
            try_name = result.name.presence
            try_username = result.username.presence

            user_params = {
              active: !require_activation,
              email: result.email,
              name: try_name || User.suggest_name(try_username || result.email),
              username: UserNameSuggester.suggest(try_username || try_name || result.email)
            }

            user = User.new(user_params)
            (config[:custom_fields] || {}).each { |k, v| user.custom_fields[k] = v }
            user.save!
          rescue => error
            result.failed = true
            result.failed_reason = error.to_s
          end
        elsif !result.email_valid && user.active
          email_token = user.email_tokens.create!(email: user.email, scope: EmailToken.scopes[:email_login])
          Jobs.enqueue(:critical_user_email,
            type: "email_login",
            user_id: user.id,
            email_token: email_token.token
          )

          user = nil
          result.failed = true
          escaped_id = Rack::Utils.escape_html("#{config_id}:#{external_id}")
          escaped_email = Rack::Utils.escape_html(result.email)
          result.failed_reason = "Es gibt bereits ein Konto für die E-Mail-Adresse #{escaped_email}. Wir haben dir einen Link an diese Adresse geschickt, mit dem du dich einloggen kannst. Falls du dich direkt einloggen können möchtest, schicke nach dem erfolgreichen Login mit dem an dich geschickten Link eine Nachricht über das Forum mit dem Code '#{escaped_id}' an die Gruppe <b>@support</b>, um diese Funktion für dein Konto freischalten zu lassen."
        end

        result.user = user
      end

      if user && !user.active
        if require_activation
          email_token = user.email_tokens.create!(email: user.email, scope: EmailToken.scopes[:signup])
          EmailToken.enqueue_signup_email(email_token)

          result.failed = true
          escaped_email = Rack::Utils.escape_html(result.email)
          result.failed_reason = "Um dein Konto zu aktivieren haben wir dir (erneut) eine E-Mail an #{escaped_email} geschickt. Bitte nutze den darin enthaltenen Link, um die Anmeldung abzuschließen"
        else
          user.active = true
          user.save!
        end
      end

      if user
        (config[:groups] || []).each do |name|
          group = Group.find_by(name: name)
          if group
            group.add(user)
            user.update(primary_group: group)
          end
        end
      end

      result
    end
  end

  def self.plugin_name
    'discourse-multi-sso'.freeze
  end

  def self.pstore_get(key)
    PluginStore.get(MultiSso.plugin_name, key)
  end
end

auth_provider title_setting: "multi_sso_button_title",
              authenticator: ::MultiSso::Authenticator.new

after_initialize do

  module ::MultiSso

  end

end
