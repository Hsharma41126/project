const User = require('./User');
const Table = require('./Table');
const MenuItem = require('./MenuItem');
const Order = require('./Order');
const OrderItem = require('./OrderItem');
const Session = require('./Session');
const Reservation = require('./Reservation');
const Device = require('./Device');
const Printer = require('./Printer');

// Define associations
// User associations
User.hasMany(Order, { foreignKey: 'created_by', as: 'orders' });
User.hasMany(Session, { foreignKey: 'created_by', as: 'sessions' });
User.hasMany(Reservation, { foreignKey: 'created_by', as: 'reservations' });

// Table associations
Table.hasMany(Order, { foreignKey: 'table_id', as: 'orders' });
Table.hasMany(Session, { foreignKey: 'table_id', as: 'sessions' });
Table.hasMany(Reservation, { foreignKey: 'table_id', as: 'reservations' });
Table.hasMany(Device, { foreignKey: 'table_id', as: 'devices' });
Table.belongsTo(Session, { foreignKey: 'current_session_id', as: 'currentSession' });

// Order associations
Order.belongsTo(User, { foreignKey: 'created_by', as: 'creator' });
Order.belongsTo(Table, { foreignKey: 'table_id', as: 'table' });
Order.hasMany(OrderItem, { foreignKey: 'order_id', as: 'items' });

// OrderItem associations
OrderItem.belongsTo(Order, { foreignKey: 'order_id', as: 'order' });
OrderItem.belongsTo(MenuItem, { foreignKey: 'menu_item_id', as: 'menuItem' });

// Session associations
Session.belongsTo(User, { foreignKey: 'created_by', as: 'creator' });
Session.belongsTo(Table, { foreignKey: 'table_id', as: 'table' });

// Reservation associations
Reservation.belongsTo(User, { foreignKey: 'created_by', as: 'creator' });
Reservation.belongsTo(Table, { foreignKey: 'table_id', as: 'table' });

// Device associations
Device.belongsTo(Table, { foreignKey: 'table_id', as: 'table' });

// MenuItem associations
MenuItem.hasMany(OrderItem, { foreignKey: 'menu_item_id', as: 'orderItems' });

module.exports = {
  User,
  Table,
  MenuItem,
  Order,
  OrderItem,
  Session,
  Reservation,
  Device,
  Printer
};