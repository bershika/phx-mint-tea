defmodule MintTea.Repo.Migrations.AlterAuthTablesAddTotp do
  use Ecto.Migration

  def change do
    alter table(:users) do
      add :totp_secret, :binary, null: true
    end

    alter table(:users_tokens) do
      add :totp_verified_at, :utc_datetime, null: true
    end
  end
end
