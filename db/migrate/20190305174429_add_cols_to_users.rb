class AddColsToUsers < ActiveRecord::Migration[5.2]
  def change
    add_column :users, :member, :string
    add_column :users, :dob, :date
  end
end
