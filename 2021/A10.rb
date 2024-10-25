# A10:2021 - Server-Side Request Forgery (SSRF)

# Descripción:
# SSRF ocurre cuando una aplicación web obtiene un recurso remoto sin validar la URL proporcionada por el usuario. Esto permite a un atacante forzar a la aplicación a enviar una solicitud manipulada a un destino inesperado, incluso cuando está protegida por un firewall, VPN, u otro tipo de lista de control de acceso a la red.
# Ejemplo vulnerable en Ruby on Rails:

require 'open-uri'

class ProfileController < ApplicationController
  def update_avatar
    avatar_url = params[:avatar_url]
    avatar_data = URI.open(avatar_url).read
    current_user.update(avatar: avatar_data)
    redirect_to profile_path, notice: 'Avatar updated successfully'
  end

  def fetch_metadata
    url = params[:url]
    response = Net::HTTP.get(URI(url))
    render json: JSON.parse(response)
  end
end

# Este código es vulnerable porque:
# Permite descargar contenido de cualquier URL sin validación.
# Permite hacer peticiones HTTP a cualquier URL proporcionada por el usuario.

# Explotación:
# Un atacante podría proporcionar URLs que apunten a recursos internos como:
# http://169.254.169.254/latest/meta-data/ (metadata de AWS EC2)
# http://localhost:8080/admin (interfaz de administración local)

# Solución:

require 'open-uri'
require 'addressable/uri'

class ProfileController < ApplicationController
  ALLOWED_HOSTS = ['example.com', 'secure-images.com']
  ALLOWED_SCHEMES = ['https']

  def update_avatar
    avatar_url = params[:avatar_url]
    if valid_url?(avatar_url)
      avatar_data = download_image(avatar_url)
      current_user.update(avatar: avatar_data)
      redirect_to profile_path, notice: 'Avatar updated successfully'
    else
      redirect_to profile_path, alert: 'Invalid avatar URL'
    end
  end

  def fetch_metadata
    url = params[:url]
    if valid_url?(url)
      response = fetch_url(url)
      render json: JSON.parse(response)
    else
      render json: { error: 'Invalid URL' }, status: :bad_request
    end
  end

  private

  def valid_url?(url)
    uri = Addressable::URI.parse(url)
    ALLOWED_HOSTS.include?(uri.host) && ALLOWED_SCHEMES.include?(uri.scheme)
  rescue Addressable::URI::InvalidURIError
    false
  end

  def download_image(url)
    uri = Addressable::URI.parse(url)
    Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
      request = Net::HTTP::Get.new(uri)
      response = http.request(request)
      response.body if response.is_a?(Net::HTTPSuccess)
    end
  end

  def fetch_url(url)
    uri = Addressable::URI.parse(url)
    Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
      request = Net::HTTP::Get.new(uri)
      response = http.request(request)
      response.body if response.is_a?(Net::HTTPSuccess)
    end
  end
end

# Estas mejoras:
# Validan la URL antes de hacer cualquier solicitud.
# Limitan los hosts y esquemas permitidos.
# Usan Addressable::URI para un parsing de URL más robusto.
# Implementan métodos separados para descargar imágenes y hacer peticiones HTTP.

# Además:
# Considera usar una lista blanca de IPs/dominios permitidos.
# Implementa timeouts para las solicitudes.
# Usa un proxy de reenvío para todas las solicitudes salientes.
# Configura firewalls para bloquear tráfico no esencial.
