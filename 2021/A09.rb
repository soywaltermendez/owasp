# A09:2021 - Security Logging and Monitoring Failures

# Descripción:
# Este riesgo se refiere a la falta o insuficiencia de logging y monitoreo de seguridad. Esto puede impedir la detección, escalada y respuesta a incidentes de seguridad activos.
# Ejemplo vulnerable en Ruby on Rails:

class ApplicationController < ActionController::Base
  def log_error(exception)
    logger.error(exception.message)
  end
end

class SessionsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      session[:user_id] = user.id
      redirect_to root_path
    else
      flash.now[:alert] = "Invalid email or password"
      render :new
    end
  end
end

# Este código es vulnerable porque:
# El logging de errores es mínimo y no incluye detalles importantes.
# No hay logging de eventos de seguridad críticos como inicios de sesión.
# No hay monitoreo activo de eventos de seguridad.

# Solución:

Rails.application.configure do
  config.lograge.enabled = true
  config.lograge.custom_options = lambda do |event|
    exceptions = %w(controller action format id)
    {
      params: event.payload[:params].except(*exceptions),
      time: Time.now,
      user_id: event.payload[:user_id],
      ip: event.payload[:ip]
    }
  end
end

class ApplicationController < ActionController::Base
  before_action :set_lograge_data

  def log_error(exception)
    error_id = SecureRandom.hex(10)
    logger.error("Error ID: #{error_id}")
    logger.error("Message: #{exception.message}")
    logger.error("Backtrace: #{exception.backtrace.join("\n")}")
    logger.error("User ID: #{current_user&.id}")
    logger.error("IP: #{request.remote_ip}")
    error_id
  end

  private

  def set_lograge_data
    lograge_custom_options[:user_id] = current_user&.id
    lograge_custom_options[:ip] = request.remote_ip
  end
end

class SessionsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      session[:user_id] = user.id
      log_login_event(user, true)
      redirect_to root_path
    else
      log_login_event(nil, false)
      flash.now[:alert] = "Invalid email or password"
      render :new
    end
  end

  private

  def log_login_event(user, success)
    event = {
      event: 'login_attempt',
      success: success,
      user_id: user&.id,
      email: params[:email],
      ip_address: request.remote_ip,
      user_agent: request.user_agent,
      timestamp: Time.now
    }
    Rails.logger.info(event.to_json)
  end
end

class Rack::Attack
  Rack::Attack.track("events/ip", limit: 300, period: 5.minutes) do |req|
    req.ip
  end

  ActiveSupport::Notifications.subscribe("rack.attack") do |name, start, finish, request_id, payload|
    req = payload[:request]
    if payload[:match_type] == :track
      Rails.logger.warn("[potential_attack] ip=#{req.ip} path=#{req.path}")
    end
  end
end

# Estas mejoras:
# Usan Lograge para un logging estructurado y consistente.
# Implementan logging detallado de errores con ID único para seguimiento.
# Registran eventos de seguridad críticos como intentos de inicio de sesión.
# Implementan monitoreo básico de tasas de solicitud con Rack::Attack.

# Además:
# Considera usar un servicio de logging centralizado (como ELK stack o Splunk).
# Implementa alertas para eventos de seguridad críticos.
# Asegúrate de que los logs no contengan datos sensibles (como contraseñas).
# Implementa rotación y retención de logs.
# Considera usar una solución de SIEM (Security Information and Event Management).
