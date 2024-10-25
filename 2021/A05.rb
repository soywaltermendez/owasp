# A05:2021 - Security Misconfiguration

# Descripción:
# Se refiere a configuraciones de seguridad incorrectas, incompletas o por defecto. Esto puede ocurrir en cualquier nivel de la aplicación, incluyendo la plataforma, el servidor web, el framework de aplicación, y el código personalizado.
# Ejemplo vulnerable en Ruby on Rails:

Rails.application.configure do
  # Configuraciones inseguras
  config.consider_all_requests_local = true
  config.action_dispatch.show_exceptions = true
  config.active_record.dump_schema_after_migration = true
  config.log_level = :debug
  config.force_ssl = false
end

Rails.application.config.session_store :cookie_store, key: '_myapp_session', secure: false, httponly: false

# Estas configuraciones son inseguras porque:
# Muestran información detallada de errores en producción.
# Permiten el volcado del esquema de la base de datos.
# Usan un nivel de logging demasiado detallado.
# No fuerzan el uso de SSL.
# No configuran adecuadamente las cookies de sesión.

# Explotación:
# Un atacante podría obtener información sensible de los mensajes de error.
# Podrían acceder a la estructura de la base de datos.
# Los logs podrían contener información sensible.
# Las comunicaciones no están encriptadas.
# Las cookies de sesión son vulnerables a ataques XSS y MITM.

# Solución:

Rails.application.configure do
  # Configuraciones seguras
  config.consider_all_requests_local = false
  config.action_dispatch.show_exceptions = false
  config.active_record.dump_schema_after_migration = false
  config.log_level = :warn
  config.force_ssl = true

  # Configuración de cabeceras de seguridad
  config.action_dispatch.default_headers = {
    'X-Frame-Options' => 'SAMEORIGIN',
    'X-XSS-Protection' => '1; mode=block',
    'X-Content-Type-Options' => 'nosniff',
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains'
  }
end

Rails.application.config.session_store :cookie_store,
  key: '_myapp_session',
  secure: Rails.env.production?,
  httponly: true,
  same_site: :lax

Rails.application.config.filter_parameters += [
  :passw, :secret, :token, :_key, :crypt, :salt, :certificate, :otp, :ssn
]

# Estas configuraciones mejoran la seguridad:
# Ocultan detalles de errores en producción.
# Deshabilitan el volcado del esquema de la base de datos.
# Reducen el nivel de logging.
# Fuerzan el uso de SSL en producción.
# Configuran correctamente las cookies de sesión.
# Añaden cabeceras de seguridad.
# Filtran parámetros sensibles en los logs.
# Además, asegúrate de:
# Mantener todas las dependencias actualizadas.
# Deshabilitar o eliminar funcionalidades no utilizadas.
# Usar un gestor de secretos para las credenciales (como Rails Credentials).
# Configurar correctamente los CORS si es necesario.
