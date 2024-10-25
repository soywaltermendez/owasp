# A02:2021 - Cryptographic Failures

# Descripción:
# Se refiere a fallas relacionadas con criptografía, que a menudo conducen a la exposición de datos sensibles. Esto incluye el uso de algoritmos débiles, manejo inadecuado de claves, o falta de encriptación donde es necesaria.

require 'digest'

class User < ApplicationRecord
  # Método inseguro para guardar contraseña
  def set_password(password)
    self.password_hash = Digest::MD5.hexdigest(password)
  end

  # Método inseguro para verificar contraseña
  def verify_password(password)
    Digest::MD5.hexdigest(password) == self.password_hash
  end

  # Método inseguro para guardar número de tarjeta
  def save_credit_card(number)
    self.credit_card = Base64.encode64(number)
  end
end

# Este código es vulnerable porque:
# Usa MD5 para hashear contraseñas, que es considerado inseguro.
# No usa salt para las contraseñas.
# Almacena números de tarjeta usando solo codificación Base64.

# Explotación:
# Las contraseñas hasheadas con MD5 son vulnerables a ataques de rainbow table.
# Los números de tarjeta pueden ser fácilmente decodificados.

# Solución:

require 'bcrypt'
require 'openssl'

class User < ApplicationRecord
  # Método seguro para guardar contraseña
  def set_password(password)
    self.password_hash = BCrypt::Password.create(password)
  end

  # Método seguro para verificar contraseña
  def verify_password(password)
    BCrypt::Password.new(self.password_hash) == password
  end

  # Método seguro para guardar número de tarjeta
  def save_credit_card(number)
    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.encrypt
    key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(ENV['SECRET_KEY'], ENV['SALT'], 20000, cipher.key_len)
    iv = cipher.random_iv

    encrypted = cipher.update(number) + cipher.final
    self.credit_card = Base64.strict_encode64(encrypted)
    self.credit_card_iv = Base64.strict_encode64(iv)
  end

  # Método para descifrar número de tarjeta
  def get_credit_card
    encrypted = Base64.strict_decode64(self.credit_card)
    iv = Base64.strict_decode64(self.credit_card_iv)

    decipher = OpenSSL::Cipher.new('AES-256-CBC')
    decipher.decrypt
    key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(ENV['SECRET_KEY'], ENV['SALT'], 20000, decipher.key_len)
    decipher.iv = iv

    decipher.update(encrypted) + decipher.final
  end
end

# Esta solución aborda los problemas criptográficos de la siguiente manera:
# Usa BCrypt para hashear contraseñas, que es más seguro que MD5 y maneja el salt automáticamente.
# Implementa encriptación AES-256-CBC para datos sensibles como números de tarjeta.
# Usa PBKDF2 para derivar la clave de encriptación, lo que hace más difícil los ataques de fuerza bruta.
# Almacena el vector de inicialización (IV) junto con los datos encriptados para permitir el descifrado.
# Recuerda manejar ENV['SECRET_KEY'] y ENV['SALT'] de forma segura y no almacenarlos en el control de versiones.
