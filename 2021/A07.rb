# A07:2021 - Identification and Authentication Failures

# Descripción:
# Este riesgo se refiere a problemas en la identificación y autenticación de usuarios, lo que puede permitir a los atacantes comprometer contraseñas, claves o tokens de sesión, o explotar otras fallas de implementación para asumir la identidad de otros usuarios.
# Ejemplo vulnerable en Ruby on Rails:

class SessionsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])
    if user && user.authenticate(params[:password])
      session[:user_id] = user.id
      redirect_to root_path
    else
      flash.now[:alert] = "Invalid email or password"
      render :new
    end
  end
end

class User < ApplicationRecord
  has_secure_password
  validates :email, presence: true, uniqueness: true
  validates :password, length: { minimum: 6 }
end

# Este código es vulnerable porque:
# No implementa protección contra ataques de fuerza bruta.
# No requiere contraseñas fuertes.
# No implementa autenticación de dos factores (2FA).
# No usa tokens de sesión seguros.

# Solución:

class SessionsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])
    if user && user.authenticate(params[:password])
      if user.two_factor_enabled?
        session[:two_factor_user_id] = user.id
        redirect_to two_factor_auth_path
      else
        log_in_user(user)
      end
    else
      flash.now[:alert] = "Invalid email or password"
      render :new
    end
  end

  private

  def log_in_user(user)
    reset_session
    session[:user_id] = user.id
    cookies.signed[:user_id] = { value: user.id, expires: 12.hours.from_now, httponly: true, secure: true }
    redirect_to root_path
  end
end

class User < ApplicationRecord
  has_secure_password
  validates :email, presence: true, uniqueness: true, format: { with: URI::MailTo::EMAIL_REGEXP }
  validate :password_complexity

  def password_complexity
    return if password.blank?
    unless password.match(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/)
      errors.add :password, 'must include at least one lowercase letter, one uppercase letter, one digit, one special character, and be at least 12 characters long'
    end
  end
end

class Rack::Attack
  throttle('login/ip', limit: 5, period: 20.seconds) do |req|
    req.ip if req.path == '/login' && req.post?
  end
end

# Estas mejoras:
# Implementan límites de tasa para prevenir ataques de fuerza bruta.
# Requieren contraseñas complejas.
# Preparan el sistema para 2FA.
# Usan tokens de sesión más seguros con httponly y secure flags.
# Implementan validación de email.

# Además:
# Considera implementar CAPTCHA después de varios intentos fallidos.
# Usa bcrypt para el hashing de contraseñas (incluido en has_secure_password).
# Implementa el cierre de sesión en todos los dispositivos después de un cambio de contraseña.
# Considera usar una gema como Devise que maneja muchos de estos problemas automáticamente.
