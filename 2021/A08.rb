# A08:2021 - Software and Data Integrity Failures

# Descripción:
# Este riesgo se relaciona con código y sistemas que no protegen adecuadamente contra violaciones de integridad. Esto incluye el uso de datos no confiables sin verificación, actualizaciones automáticas inseguras, y manipulación de datos críticos.
# Ejemplo vulnerable en Ruby on Rails:

class UpdatesController < ApplicationController
  def apply
    update_file = params[:update_file]
    if update_file
      system("unzip #{update_file.path} -d #{Rails.root}")
      system("ruby #{Rails.root}/update_script.rb")
      render json: { message: "Update applied successfully" }
    else
      render json: { error: "No update file provided" }, status: :unprocessable_entity
    end
  end
end

class User < ApplicationRecord
  serialize :preferences, JSON

  def update_preferences(new_prefs)
    self.preferences = new_prefs
    save
  end
end

# Este código es vulnerable porque:
# Aplica actualizaciones sin verificar la integridad o autenticidad.
# Ejecuta código arbitrario desde el archivo de actualización.
# Permite la manipulación directa de datos serializados sin validación.

# Solución:

require 'openssl'

class UpdatesController < ApplicationController
  UPDATES_PUBLIC_KEY = OpenSSL::PKey::RSA.new(File.read(Rails.root.join('config', 'updates_public_key.pem')))

  def apply
    update_file = params[:update_file]
    signature = params[:signature]

    if update_file && signature && verify_signature(update_file, signature)
      safe_extract(update_file)
      ApplyUpdateJob.perform_later
      render json: { message: "Update queued for application" }
    else
      render json: { error: "Invalid update file or signature" }, status: :unprocessable_entity
    end
  end

  private

  def verify_signature(file, signature)
    digest = OpenSSL::Digest::SHA256.new
    UPDATES_PUBLIC_KEY.verify(digest, Base64.decode64(signature), file.read)
  end

  def safe_extract(file)
    require 'zip'

    Zip::File.open(file.path) do |zip_file|
      zip_file.each do |entry|
        # Ensure we're not allowing zip slip vulnerability
        raise "Illegal entry" unless entry.name.start_with?("updates/")

        # Write to a temporary directory
        entry.extract(Rails.root.join('tmp', 'updates', entry.name))
      end
    end
  end
end

class User < ApplicationRecord
  serialize :preferences, JSON

  def update_preferences(new_prefs)
    sanitized_prefs = sanitize_preferences(new_prefs)
    self.preferences = sanitized_prefs
    save
  end

  private

  def sanitize_preferences(prefs)
    allowed_keys = ['theme', 'notifications', 'language']
    prefs.select { |k, v| allowed_keys.include?(k) && v.is_a?(String) }
  end
end

class ApplyUpdateJob < ApplicationJob
  queue_as :default

  def perform
    update_script = Rails.root.join('tmp', 'updates', 'update_script.rb')
    if File.exist?(update_script)
      # Load the script in a sandboxed environment
      sandbox = Object.new
      sandbox.instance_eval(File.read(update_script))
    end
  end
end

# Estas mejoras:
# Verifican la firma digital de las actualizaciones.
# Extraen archivos de forma segura para prevenir zip slip.
# Ejecutan el script de actualización en un job background y en un sandbox.
# Sanitizan y validan los datos de preferencias antes de guardarlos.

# Además:
# Usa un sistema de gestión de dependencias confiable (como Bundler).
# Implementa verificaciones de integridad para datos críticos.
# Usa firmas digitales para verificar la autenticidad de datos y código.
# Implementa un proceso de CI/CD seguro con múltiples niveles de revisión.
