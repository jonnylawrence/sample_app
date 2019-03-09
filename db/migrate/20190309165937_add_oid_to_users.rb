class AddOidToUsers < ActiveRecord::Migration[5.2]
  def change
    add_column :users, :oid, :string
    add_index :users, :oid, unique: true
  end
end
