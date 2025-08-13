const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const MenuItem = sequelize.define('MenuItem', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  name: {
    type: DataTypes.STRING(100),
    allowNull: false,
    validate: {
      notEmpty: true
    }
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  category: {
    type: DataTypes.ENUM('Food', 'Drinks', 'Games', 'Beverages', 'Mixed'),
    allowNull: false
  },
  subcategory: {
    type: DataTypes.STRING(50),
    allowNull: false
  },
  price: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false,
    validate: {
      min: 0
    }
  },
  image: {
    type: DataTypes.STRING(255),
    allowNull: true
  },
  // Printer routing
  printer: {
    type: DataTypes.ENUM('Kitchen Printer', 'Bar Printer', 'Main Printer', 'Game Zone Printer'),
    allowNull: false
  },
  // Item availability
  is_available: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  // Item variants/types
  variants: {
    type: DataTypes.JSON,
    defaultValue: []
  },
  // Nutritional info
  nutritional_info: {
    type: DataTypes.JSON,
    defaultValue: {}
  },
  preparation_time: {
    type: DataTypes.INTEGER,
    defaultValue: 15,
    comment: 'Preparation time in minutes'
  },
  is_popular: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
}, {
  tableName: 'menu_items'
});

module.exports = MenuItem;