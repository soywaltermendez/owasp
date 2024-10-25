# A01:2021 - Broken Access Control

# Descripción:
# Es cuando un sistema falla en restringir adecuadamente el acceso a recursos o funcionalidades, permitiendo a usuarios no autorizados realizar acciones o acceder a datos que no deberían.

class UsersController < ApplicationController
  def show
    @user = User.find(params[:id])
    render json: @user
  end
end

# Este código es vulnerable porque cualquier usuario autenticado puede acceder a los datos de cualquier otro usuario simplemente cambiando el ID en la URL.
# Explotación:
# Un atacante podría hacer requests a /users/1, /users/2, etc., obteniendo datos de todos los usuarios.

# Solución:

class UsersController < ApplicationController
  before_action :authorize_user

  def show
    @user = User.find(params[:id])
    render json: @user
  end

  private

  def authorize_user
    unless current_user.id == params[:id].to_i
      render json: { error: 'Unauthorized' }, status: :forbidden
    end
  end
end

# Este código verifica que el usuario actual solo pueda acceder a su propia información.
