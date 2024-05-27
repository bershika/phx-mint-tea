defmodule MintTeaWeb.UserVerifyTotpLive do
  use MintTeaWeb, :live_view

  alias MintTea.Accounts

  def render(assigns) do
    ~H"""
    <div class="mx-auto max-w-sm">
      <.header class="text-center">
        Two-factor auth required
        <:subtitle>
          Sign in to your verification app to find the code.
        </:subtitle>
      </.header>

      <.simple_form for={@totp_form} id="verify_totp" phx-submit="verify_totp">
        <.input field={@totp_form[:code]} label="Verification code" required />
        <:actions>
          <.button phx-disable-with="Verifying..." class="w-full">
            Verify
          </.button>
        </:actions>
      </.simple_form>
    </div>
    """
  end

  def mount(_params, %{"user_token" => user_token} = session, socket) do
    socket =
      socket
      |> assign(:user_token, user_token)
      |> assign(:return_to, session["user_return_to"] || ~p"/")
      |> assign(:totp_form, to_form(%{}, as: :totp))

    {:ok, socket}
  end

  def handle_event("verify_totp", %{"totp" => %{"code" => code}}, socket) do
    user = socket.assigns.current_user
    user_token = socket.assigns.user_token

    case Accounts.verify_session_totp(user_token, user.totp_secret, code) do
      :ok ->
        {:noreply, push_redirect(socket, to: socket.assigns.return_to)}

      {:error, :invalid_code} ->
        {:noreply, put_flash(socket, :error, "Invalid two-factor verification code.")}
    end
  end
end