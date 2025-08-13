const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Reservation = sequelize.define('Reservation', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  reservation_id: {
    type: DataTypes.STRING(50),
    allowNull: false,
    unique: true
  },
  customer_name: {
    type: DataTypes.STRING(100),
    allowNull: false
  },
  customer_phone: {
    type: DataTypes.STRING(20),
    allowNull: false
  },
  customer_email: {
    type: DataTypes.STRING(100),
    allowNull: true,
    validate: {
      isEmail: true
    }
  },
  table_id: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'tables',
      key: 'id'
    }
  },
  table_type: {
    type: DataTypes.ENUM('Snooker Table', 'Pool Table', 'PlayStation Station', 'Restaurant Table', 'Dining Table'),
    allowNull: false
  },
  // Reservation timing
  reservation_date: {
    type: DataTypes.DATEONLY,
    allowNull: false
  },
  reservation_time: {
    type: DataTypes.TIME,
    allowNull: false
  },
  duration: {
    type: DataTypes.INTEGER,
    defaultValue: 2,
    comment: 'Duration in hours'
  },
  // Party details
  party_size: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 2,
    validate: {
      min: 1
    }
  },
  special_requests: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  // Status
  status: {
    type: DataTypes.ENUM('confirmed', 'arrived', 'cancelled', 'completed', 'no-show'),
    defaultValue: 'confirmed'
  },
  // Notifications
  sms_notification: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  email_notification: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  // Pricing
  advance_payment: {
    type: DataTypes.DECIMAL(10, 2),
    defaultValue: 0.00
  },
  total_amount: {
    type: DataTypes.DECIMAL(10, 2),
    defaultValue: 0.00
  },
  // Staff who created the reservation
  created_by: {
    type: DataTypes.INTEGER,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id'
    }
  }
}, {
  tableName: 'reservations',
  hooks: {
    beforeCreate: async (reservation) => {
      if (!reservation.reservation_id) {
        const date = new Date();
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
        reservation.reservation_id = `RES-${year}${month}${day}-${random}`;
      }
    }
  }
});

module.exports = Reservation;