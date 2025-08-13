const express = require('express');
const { body, validationResult } = require('express-validator');
const MenuItem = require('../models/MenuItem');
const { auth, authorize } = require('../middleware/auth');

const router = express.Router();

// Get all menu items
router.get('/', async (req, res) => {
  try {
    const { category, subcategory, available } = req.query;
    
    let whereClause = {};
    if (category) whereClause.category = category;
    if (subcategory) whereClause.subcategory = subcategory;
    if (available !== undefined) whereClause.is_available = available === 'true';

    const menuItems = await MenuItem.findAll({
      where: whereClause,
      order: [['category', 'ASC'], ['subcategory', 'ASC'], ['name', 'ASC']]
    });

    // Group by category and subcategory
    const groupedMenu = {};
    menuItems.forEach(item => {
      if (!groupedMenu[item.category]) {
        groupedMenu[item.category] = {};
      }
      if (!groupedMenu[item.category][item.subcategory]) {
        groupedMenu[item.category][item.subcategory] = [];
      }
      groupedMenu[item.category][item.subcategory].push(item);
    });

    res.json({
      success: true,
      data: { 
        menuItems,
        groupedMenu
      }
    });
  } catch (error) {
    console.error('Get menu items error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get single menu item
router.get('/:id', async (req, res) => {
  try {
    const menuItem = await MenuItem.findByPk(req.params.id);

    if (!menuItem) {
      return res.status(404).json({
        success: false,
        message: 'Menu item not found'
      });
    }

    res.json({
      success: true,
      data: { menuItem }
    });
  } catch (error) {
    console.error('Get menu item error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Create menu item (Admin/Manager only)
router.post('/', auth, authorize('Admin', 'Manager'), [
  body('name').trim().notEmpty().withMessage('Item name is required'),
  body('category').isIn(['Food', 'Drinks', 'Games', 'Beverages', 'Mixed']).withMessage('Invalid category'),
  body('subcategory').trim().notEmpty().withMessage('Subcategory is required'),
  body('price').isFloat({ min: 0 }).withMessage('Price must be a positive number'),
  body('printer').isIn(['Kitchen Printer', 'Bar Printer', 'Main Printer', 'Game Zone Printer']).withMessage('Invalid printer')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const {
      name,
      description,
      category,
      subcategory,
      price,
      image,
      printer,
      variants,
      nutritional_info,
      preparation_time,
      is_popular
    } = req.body;

    const menuItem = await MenuItem.create({
      name,
      description,
      category,
      subcategory,
      price,
      image,
      printer,
      variants: variants || [],
      nutritional_info: nutritional_info || {},
      preparation_time: preparation_time || 15,
      is_popular: is_popular || false
    });

    res.status(201).json({
      success: true,
      message: 'Menu item created successfully',
      data: { menuItem }
    });
  } catch (error) {
    console.error('Create menu item error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update menu item
router.put('/:id', auth, authorize('Admin', 'Manager'), async (req, res) => {
  try {
    const menuItem = await MenuItem.findByPk(req.params.id);
    if (!menuItem) {
      return res.status(404).json({
        success: false,
        message: 'Menu item not found'
      });
    }

    const {
      name,
      description,
      category,
      subcategory,
      price,
      image,
      printer,
      variants,
      nutritional_info,
      preparation_time,
      is_popular,
      is_available
    } = req.body;

    await menuItem.update({
      name: name || menuItem.name,
      description: description !== undefined ? description : menuItem.description,
      category: category || menuItem.category,
      subcategory: subcategory || menuItem.subcategory,
      price: price !== undefined ? price : menuItem.price,
      image: image !== undefined ? image : menuItem.image,
      printer: printer || menuItem.printer,
      variants: variants || menuItem.variants,
      nutritional_info: nutritional_info || menuItem.nutritional_info,
      preparation_time: preparation_time !== undefined ? preparation_time : menuItem.preparation_time,
      is_popular: is_popular !== undefined ? is_popular : menuItem.is_popular,
      is_available: is_available !== undefined ? is_available : menuItem.is_available
    });

    res.json({
      success: true,
      message: 'Menu item updated successfully',
      data: { menuItem }
    });
  } catch (error) {
    console.error('Update menu item error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Toggle menu item availability
router.patch('/:id/availability', auth, authorize('Admin', 'Manager'), async (req, res) => {
  try {
    const menuItem = await MenuItem.findByPk(req.params.id);
    if (!menuItem) {
      return res.status(404).json({
        success: false,
        message: 'Menu item not found'
      });
    }

    await menuItem.update({ 
      is_available: !menuItem.is_available 
    });

    res.json({
      success: true,
      message: `Menu item ${menuItem.is_available ? 'enabled' : 'disabled'} successfully`,
      data: { menuItem }
    });
  } catch (error) {
    console.error('Toggle availability error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Delete menu item (Admin only)
router.delete('/:id', auth, authorize('Admin'), async (req, res) => {
  try {
    const menuItem = await MenuItem.findByPk(req.params.id);
    if (!menuItem) {
      return res.status(404).json({
        success: false,
        message: 'Menu item not found'
      });
    }

    await menuItem.destroy();

    res.json({
      success: true,
      message: 'Menu item deleted successfully'
    });
  } catch (error) {
    console.error('Delete menu item error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get categories and subcategories
router.get('/structure/categories', async (req, res) => {
  try {
    const menuItems = await MenuItem.findAll({
      attributes: ['category', 'subcategory'],
      group: ['category', 'subcategory'],
      order: [['category', 'ASC'], ['subcategory', 'ASC']]
    });

    const structure = {};
    menuItems.forEach(item => {
      if (!structure[item.category]) {
        structure[item.category] = [];
      }
      if (!structure[item.category].includes(item.subcategory)) {
        structure[item.category].push(item.subcategory);
      }
    });

    res.json({
      success: true,
      data: { structure }
    });
  } catch (error) {
    console.error('Get categories error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;