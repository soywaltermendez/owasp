# A04:2021 - Insecure Design

# Descripción:
# Se refiere a fallas en el diseño y la arquitectura de seguridad. Esto ocurre cuando las amenazas, los casos de uso y los límites de seguridad no se consideran durante la fase de diseño del software.
# Ejemplo vulnerable en Ruby on Rails:

class PasswordResetsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])
    if user
      token = SecureRandom.hex(10)
      user.update(reset_token: token)
      PasswordMailer.reset_email(user, token).deliver_now
      render json: { message: "Password reset instructions sent" }
    else
      render json: { error: "Email not found" }, status: :not_found
    end
  end

  def update
    user = User.find_by(reset_token: params[:token])
    if user
      user.update(password: params[:password], reset_token: nil)
      render json: { message: "Password updated successfully" }
    else
      render json: { error: "Invalid token" }, status: :unprocessable_entity
    end
  end
end

# Este diseño es inseguro porque:
# Revela si un email existe o no en el sistema.
# No tiene límite de intentos para restablecer la contraseña.
# El token de restablecimiento no expira.
# No verifica la fortaleza de la nueva contraseña.

# Explotación:
# Un atacante podría enumerar emails válidos.
# Podría intentar adivinar tokens de restablecimiento indefinidamente.
# Un token comprometido podría ser usado en cualquier momento.
# Se podrían establecer contraseñas débiles.

# Solución:

class PasswordResetsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])
    if user
      token = SecureRandom.urlsafe_base64(32)
      expiration = 1.hour.from_now
      user.update(reset_token: token, reset_token_expires_at: expiration)
      PasswordMailer.reset_email(user, token).deliver_later
    end
    # Siempre devolver el mismo mensaje
    render json: { message: "If your email exists in our system, you will receive reset instructions shortly" }
  end

  def update
    user = User.find_by(reset_token: params[:token])
    if user && user.reset_token_expires_at > Time.current && strong_password?(params[:password])
      user.update(password: params[:password], reset_token: nil, reset_token_expires_at: nil)
      render json: { message: "Password updated successfully" }
    else
      render json: { error: "Invalid or expired token, or weak password" }, status: :unprocessable_entity
    end
  end

  private

  def strong_password?(password)
    # Implementa tu lógica de validación de contraseña fuerte aquí
    password.length >= 12 && password =~ /[A-Z]/ && password =~ /[a-z]/ && password =~ /[0-9]/ && password =~ /[^A-Za-z0-9]/
  end
end

class Rack::Attack
  throttle('password_resets/ip', limit: 5, period: 1.hour) do |req|
    req.ip if req.path == '/password_resets' && req.post?
  end
end

# Este diseño mejorado:
# No revela si un email existe.
# Limita los intentos de restablecimiento de contraseña.
# Hace que los tokens expiren después de una hora.
# Verifica la fortaleza de la nueva contraseña.
# Usa deliver_later para manejar el envío de correos de forma asíncrona.
