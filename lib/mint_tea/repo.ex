defmodule MintTea.Repo do
  use Ecto.Repo,
    otp_app: :mint_tea,
    adapter: Ecto.Adapters.Postgres
end
