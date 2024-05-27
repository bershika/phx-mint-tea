defmodule MintTeaWeb.UserSettingsLive do
  use MintTeaWeb, :live_view

  alias MintTea.Accounts

  def render(assigns) do
    ~H"""
    <.header class="text-center">
      Account Settings
      <:subtitle>Manage your account email address and password settings</:subtitle>
    </.header>

    <div class="space-y-12 divide-y">
      <div>
        <.simple_form
          for={@email_form}
          id="email_form"
          phx-submit="update_email"
          phx-change="validate_email"
        >
          <.input field={@email_form[:email]} type="email" label="Email" required />
          <.input
            field={@email_form[:current_password]}
            name="current_password"
            id="current_password_for_email"
            type="password"
            label="Current password"
            value={@email_form_current_password}
            required
          />
          <:actions>
            <.button phx-disable-with="Changing...">Change Email</.button>
          </:actions>
        </.simple_form>
      </div>
      <div>
        <.simple_form
          for={@password_form}
          id="password_form"
          action={~p"/users/log_in?_action=password_updated"}
          method="post"
          phx-change="validate_password"
          phx-submit="update_password"
          phx-trigger-action={@trigger_submit}
        >
          <input
            name={@password_form[:email].name}
            type="hidden"
            id="hidden_user_email"
            value={@current_email}
          />
          <.input field={@password_form[:password]} type="password" label="New password" required />
          <.input
            field={@password_form[:password_confirmation]}
            type="password"
            label="Confirm new password"
          />
          <.input
            field={@password_form[:current_password]}
            name="current_password"
            type="password"
            label="Current password"
            id="current_password_for_password"
            value={@current_password}
            required
          />
          <:actions>
            <.button phx-disable-with="Changing...">Change Password</.button>
          </:actions>
        </.simple_form>
      </div>
            <div>
        <div :if={@totp_state == :disabled} class="mt-11">
          <.button phx-click="enable_totp">Enable Two-Factor Authentication</.button>
        </div>

        <div :if={@totp_state == :enabled} class="mt-11">
          <.button phx-click="disable_totp">Disable Two-Factor Authentication</.button>
        </div>

        <.simple_form
          :if={@totp_state == :verifying}
          for={@totp_form}
          id="totp_form"
          phx-submit="verify_totp"
        >
          <img
            src={Accounts.totp_data_uri(@current_user, @totp_secret)}
            class="h-64 inline-block border border-zinc-300 rounded-lg"
          />
          <.input field={@totp_form[:code]} label="Verification code" required />
          <:actions>
            <.button phx-disable-with="Verifying...">Verify & Enable</.button>
          </:actions>
        </.simple_form>
      </div>
    </div>
    """
  end

  def mount(%{"token" => token}, _session, socket) do
    socket =
      case Accounts.update_user_email(socket.assigns.current_user, token) do
        :ok ->
          put_flash(socket, :info, "Email changed successfully.")

        :error ->
          put_flash(socket, :error, "Email change link is invalid or it has expired.")
      end

    {:ok, push_navigate(socket, to: ~p"/users/settings")}
  end

  def mount(_params, %{"user_token" => user_token}, socket) do
    user = socket.assigns.current_user
    email_changeset = Accounts.change_user_email(user)
    password_changeset = Accounts.change_user_password(user)

    socket =
      socket
      |> assign(:user_token, user_token)
      |> assign(:current_password, nil)
      |> assign(:email_form_current_password, nil)
      |> assign(:current_email, user.email)
      |> assign(:email_form, to_form(email_changeset))
      |> assign(:password_form, to_form(password_changeset))
      |> assign(:trigger_submit, false)
      |> assign(:totp_form, to_form(%{}, as: :totp))
      |> assign(:totp_state, if(Accounts.totp_enabled?(user), do: :enabled, else: :disabled))

    {:ok, socket}
  end

  def handle_event("validate_email", params, socket) do
    %{"current_password" => password, "user" => user_params} = params

    email_form =
      socket.assigns.current_user
      |> Accounts.change_user_email(user_params)
      |> Map.put(:action, :validate)
      |> to_form()

    {:noreply, assign(socket, email_form: email_form, email_form_current_password: password)}
  end

  def handle_event("update_email", params, socket) do
    %{"current_password" => password, "user" => user_params} = params
    user = socket.assigns.current_user

    case Accounts.apply_user_email(user, password, user_params) do
      {:ok, applied_user} ->
        Accounts.deliver_user_update_email_instructions(
          applied_user,
          user.email,
          &url(~p"/users/settings/confirm_email/#{&1}")
        )

        info = "A link to confirm your email change has been sent to the new address."
        {:noreply, socket |> put_flash(:info, info) |> assign(email_form_current_password: nil)}

      {:error, changeset} ->
        {:noreply, assign(socket, :email_form, to_form(Map.put(changeset, :action, :insert)))}
    end
  end

  def handle_event("validate_password", params, socket) do
    %{"current_password" => password, "user" => user_params} = params

    password_form =
      socket.assigns.current_user
      |> Accounts.change_user_password(user_params)
      |> Map.put(:action, :validate)
      |> to_form()

    {:noreply, assign(socket, password_form: password_form, current_password: password)}
  end

  def handle_event("update_password", params, socket) do
    %{"current_password" => password, "user" => user_params} = params
    user = socket.assigns.current_user

    case Accounts.update_user_password(user, password, user_params) do
      {:ok, user} ->
        password_form =
          user
          |> Accounts.change_user_password(user_params)
          |> to_form()

        {:noreply, assign(socket, trigger_submit: true, password_form: password_form)}

      {:error, changeset} ->
        {:noreply, assign(socket, password_form: to_form(changeset))}
    end
  end
  
  ## TOTP settings

  def handle_event("enable_totp", _params, socket) do
    socket =
      socket
      |> assign(:totp_state, :verifying)
      |> assign(:totp_secret, Accounts.totp_secret())

    {:noreply, socket}
  end

  def handle_event("disable_totp", _params, socket) do
    {:ok, user} = Accounts.disable_user_totp(socket.assigns.current_user)

    socket =
      socket
      |> assign(:current_user, user)
      |> assign(:totp_state, :disabled)
      |> put_flash(:info, "Disabled two-factor authentication.")

    {:noreply, socket}
  end

  def handle_event("verify_totp", %{"totp" => %{"code" => code}}, socket) do
    user = socket.assigns.current_user
    user_token = socket.assigns.user_token
    totp_secret = socket.assigns.totp_secret

    case Accounts.enable_user_totp(user, user_token, totp_secret, code) do
      {:ok, user} ->
        socket =
          socket
          |> assign(:current_user, user)
          |> assign(:totp_state, :enabled)
          |> put_flash(:info, "Enabled two-factor authentication.")

        {:noreply, socket}

      {:error, :invalid_code} ->
        {:noreply, put_flash(socket, :error, "Invalid two-factor verification code.")}
    end
  end
end
