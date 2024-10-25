# A06:2021 - Vulnerable and Outdated Components

# Descripción:
# Se refiere al uso de componentes (como bibliotecas, frameworks y otros módulos de software) que tienen vulnerabilidades conocidas o están desactualizados. Esto puede llevar a una amplia gama de posibles ataques dependiendo de la naturaleza de la vulnerabilidad.
# Ejemplo vulnerable en Ruby on Rails:

source 'https://rubygems.org'

gem 'rails', '5.2.3'
gem 'nokogiri', '1.8.5'
gem 'devise', '4.6.0'
gem 'jquery-rails', '4.3.3'

# Este Gemfile es vulnerable porque:
# Usa una versión desactualizada de Rails (5.2.3).
# Nokogiri 1.8.5 tiene vulnerabilidades conocidas.
# Devise 4.6.0 tiene problemas de seguridad reportados.
# jQuery 4.3.3 podría tener vulnerabilidades XSS.

# Explotación:
# Un atacante podría aprovechar las vulnerabilidades conocidas en estas versiones específicas de las gemas para comprometer la aplicación.

# Solución:

source 'https://rubygems.org'

gem 'rails', '~> 7.0.6'
gem 'nokogiri', '~> 1.15.3'
gem 'devise', '~> 4.9.2'
# Considera si realmente necesitas jQuery
# gem 'jquery-rails'

Rails.application.config.content_security_policy do |policy|
  policy.default_src :self, :https
  policy.font_src    :self, :https, :data
  policy.img_src     :self, :https, :data
  policy.object_src  :none
  policy.script_src  :self, :https
  policy.style_src   :self, :https
  policy.connect_src :self, :https
  policy.frame_ancestors :none
  policy.base_uri :self
  policy.form_action :self
end

# Estas mejoras:
# Actualizan Rails a la última versión estable.
# Usan versiones recientes y seguras de Nokogiri y Devise.
# Eliminan jQuery si no es estrictamente necesario.
# Implementan una Content Security Policy para mitigar riesgos de XSS.

# Además:
# Usa el operador ~> para permitir actualizaciones de parches de seguridad.
