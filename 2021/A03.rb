# A03:2021 - Injection

# Descripción:
# La inyección ocurre cuando datos no confiables son enviados a un intérprete como parte de un comando o consulta. Los datos hostiles del atacante pueden engañar al intérprete para que ejecute comandos no deseados o acceda a datos sin la autorización adecuada.
# Ejemplo vulnerable en Ruby on Rails:

class ProductsController < ApplicationController
  def search
    query = params[:query]
    @products = Product.where("name LIKE '%#{query}%' OR description LIKE '%#{query}%'")
    render json: @products
  end
end

# Este código es vulnerable a SQL Injection porque concatena directamente el input del usuario en la consulta SQL.
# Explotación:
# Un atacante podría enviar una consulta como ' OR '1'='1, resultando en una consulta SQL que devuelve todos los productos:

SELECT * FROM products WHERE name LIKE '%' OR '1'='1%' OR description LIKE '%' OR '1'='1%'

# Solución:

class ProductsController < ApplicationController
  def search
    query = params[:query]
    @products = Product.where("name LIKE :query OR description LIKE :query", query: "%#{query}%")
    render json: @products
  end
end

# Esta solución usa consultas parametrizadas, que separan la estructura SQL de los datos, previniendo la inyección SQL.
