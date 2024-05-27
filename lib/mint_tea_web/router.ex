defmodule MintTeaWeb.Router do
  use MintTeaWeb, :router

  import MintTeaWeb.UserAuth

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {MintTeaWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :fetch_current_user
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/", MintTeaWeb do
    pipe_through :browser

    get "/", PageController, :home
  end

  # Other scopes may use custom stacks.
  # scope "/api", MintTeaWeb do
  #   pipe_through :api
  # end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:mint_tea, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: MintTeaWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end

  # ## Authentication routes

  # scope "/", MintTeaWeb do
  #   pipe_through [:browser, :redirect_if_user_is_authenticated]

  #   get "/users/register", UserRegistrationController, :new
  #   post "/users/register", UserRegistrationController, :create
  #   get "/users/log_in", UserSessionController, :new
  #   post "/users/log_in", UserSessionController, :create
  #   get "/users/reset_password", UserResetPasswordController, :new
  #   post "/users/reset_password", UserResetPasswordController, :create
  #   get "/users/reset_password/:token", UserResetPasswordController, :edit
  #   put "/users/reset_password/:token", UserResetPasswordController, :update
  # end

  # scope "/", MintTeaWeb do
  #   pipe_through [:browser, :require_authenticated_user]

  #   get "/users/settings", UserSettingsController, :edit
  #   put "/users/settings", UserSettingsController, :update
  #   get "/users/settings/confirm_email/:token", UserSettingsController, :confirm_email
  # end

  # scope "/", MintTeaWeb do
  #   pipe_through [:browser]

  #   delete "/users/log_out", UserSessionController, :delete
  #   get "/users/confirm", UserConfirmationController, :new
  #   post "/users/confirm", UserConfirmationController, :create
  #   get "/users/confirm/:token", UserConfirmationController, :edit
  #   post "/users/confirm/:token", UserConfirmationController, :update
  # end

  ## Authentication routes

  scope "/", MintTeaWeb do
    pipe_through [:browser, :redirect_if_user_is_authenticated]

    live_session :redirect_if_user_is_authenticated,
      on_mount: [{MintTeaWeb.UserAuth, :redirect_if_user_is_authenticated}] do
      live "/users/register", UserRegistrationLive, :new
      live "/users/log_in", UserLoginLive, :new
      live "/users/reset_password", UserForgotPasswordLive, :new
      live "/users/reset_password/:token", UserResetPasswordLive, :edit
    end

    post "/users/log_in", UserSessionController, :create
  end

  scope "/", MintTeaWeb do
    pipe_through [:browser, :require_authenticated_user]

    live_session :require_authenticated_user,
      on_mount: [{MintTeaWeb.UserAuth, :ensure_authenticated}] do
      live "/users/verify-totp", UserVerifyTotpLive, :verify
    end
  end

  scope "/", MintTeaWeb do
    pipe_through [:browser, :require_authenticated_user, :require_verified_totp]

    live_session :require_verified_totp_user,
      on_mount: [
        {MintTeaWeb.UserAuth, :ensure_authenticated},
        {MintTeaWeb.UserAuth, :ensure_verified_totp}
      ] do
      live "/users/settings", UserSettingsLive, :edit
      live "/users/settings/confirm_email/:token", UserSettingsLive, :confirm_email
    end
  end

  scope "/", MintTeaWeb do
    pipe_through [:browser]

    delete "/users/log_out", UserSessionController, :delete

    live_session :current_user,
      on_mount: [{MintTeaWeb.UserAuth, :mount_current_user}] do
      live "/users/confirm/:token", UserConfirmationLive, :edit
      live "/users/confirm", UserConfirmationInstructionsLive, :new
    end
  end
end
