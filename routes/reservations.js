const express = require('express');
const { body, validationResult } = require('express-validator');
const { Reservation, Table, User } = require('../models');
const { auth } = require('../middleware/auth');

const router = express.Router();

// Get all reservations
router.get('/', auth, async (req, res) => {
  try {
    const { status, date, table_type } = req.query;
    
    let whereClause = {};
    if (status) whereClause.status = status;
    if (table_type) whereClause.table_type = table_type;
    if (date) whereClause.reservation_date = date;

    const reservations = await Reservation.findAll({
      where: whereClause,
      include: [
        {
          model: Table,
          as: 'table',
          required: false
        },
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'name', 'username'],
          required: false
        }
      ],
      order: [['reservation_date', 'ASC'], ['reservation_time', 'ASC']]
    });

    res.json({
      success: true,
      data: { reservations }
    });
  } catch (error) {
    console.error('Get reservations error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get single reservation
router.get('/:id', auth, async (req, res) => {
  try {
    const reservation = await Reservation.findByPk(req.params.id, {
      include: [
        {
          model: Table,
          as: 'table',
          required: false
        },
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'name', 'username'],
          required: false
        }
      ]
    });

    if (!reservation) {
      return res.status(404).json({
        success: false,
        message: 'Reservation not found'
      });
    }

    res.json({
      success: true,
      data: { reservation }
    });
  } catch (error) {
    console.error('Get reservation error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Create reservation
router.post('/', [
  body('customer_name').trim().notEmpty().withMessage('Customer name is required'),
  body('customer_phone').trim().notEmpty().withMessage('Customer phone is required'),
  body('table_type').isIn(['Snooker Table', 'Pool Table', 'PlayStation Station', 'Restaurant Table', 'Dining Table']).withMessage('Invalid table type'),
  body('reservation_date').isISO8601().withMessage('Valid reservation date is required'),
  body('reservation_time').matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).withMessage('Valid reservation time is required (HH:MM format)'),
  body('party_size').isInt({ min: 1 }).withMessage('Party size must be at least 1')
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
      customer_name,
      customer_phone,
      customer_email,
      table_type,
      reservation_date,
      reservation_time,
      duration = 2,
      party_size,
      special_requests,
      sms_notification = true,
      email_notification = true
    } = req.body;

    // Check for available tables of the requested type
    const availableTables = await Table.findAll({
      where: {
        type: table_type.replace(' Table', '').replace(' Station', ''),
        status: 'available',
        is_active: true
      }
    });

    if (availableTables.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No tables available for the selected type'
      });
    }

    // Check for conflicting reservations
    const conflictingReservations = await Reservation.findAll({
      where: {
        table_type,
        reservation_date,
        reservation_time,
        status: ['confirmed', 'arrived']
      }
    });

    if (conflictingReservations.length >= availableTables.length) {
      return res.status(400).json({
        success: false,
        message: 'No tables available at the requested time'
      });
    }

    // Assign a table (simple assignment to first available)
    const assignedTable = availableTables[0];

    const reservation = await Reservation.create({
      customer_name,
      customer_phone,
      customer_email,
      table_id: assignedTable.id,
      table_type,
      reservation_date,
      reservation_time,
      duration,
      party_size,
      special_requests,
      sms_notification,
      email_notification,
      created_by: req.user?.id || null
    });

    const completeReservation = await Reservation.findByPk(reservation.id, {
      include: [
        {
          model: Table,
          as: 'table'
        }
      ]
    });

    res.status(201).json({
      success: true,
      message: 'Reservation created successfully',
      data: { reservation: completeReservation }
    });
  } catch (error) {
    console.error('Create reservation error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update reservation status
router.patch('/:id/status', auth, [
  body('status').isIn(['confirmed', 'arrived', 'cancelled', 'completed', 'no-show']).withMessage('Invalid status')
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

    const { status } = req.body;
    const reservation = await Reservation.findByPk(req.params.id);

    if (!reservation) {
      return res.status(404).json({
        success: false,
        message: 'Reservation not found'
      });
    }

    await reservation.update({ status });

    // If marking as arrived, update table status
    if (status === 'arrived' && reservation.table_id) {
      await Table.update(
        { status: 'reserved' },
        { where: { id: reservation.table_id } }
      );
    }

    // If cancelling or completing, free up the table
    if (['cancelled', 'completed', 'no-show'].includes(status) && reservation.table_id) {
      await Table.update(
        { status: 'available' },
        { where: { id: reservation.table_id } }
      );
    }

    res.json({
      success: true,
      message: 'Reservation status updated successfully',
      data: { reservation }
    });
  } catch (error) {
    console.error('Update reservation status error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update reservation
router.put('/:id', auth, async (req, res) => {
  try {
    const reservation = await Reservation.findByPk(req.params.id);
    if (!reservation) {
      return res.status(404).json({
        success: false,
        message: 'Reservation not found'
      });
    }

    const {
      customer_name,
      customer_phone,
      customer_email,
      table_type,
      reservation_date,
      reservation_time,
      duration,
      party_size,
      special_requests
    } = req.body;

    await reservation.update({
      customer_name: customer_name || reservation.customer_name,
      customer_phone: customer_phone || reservation.customer_phone,
      customer_email: customer_email !== undefined ? customer_email : reservation.customer_email,
      table_type: table_type || reservation.table_type,
      reservation_date: reservation_date || reservation.reservation_date,
      reservation_time: reservation_time || reservation.reservation_time,
      duration: duration !== undefined ? duration : reservation.duration,
      party_size: party_size !== undefined ? party_size : reservation.party_size,
      special_requests: special_requests !== undefined ? special_requests : reservation.special_requests
    });

    res.json({
      success: true,
      message: 'Reservation updated successfully',
      data: { reservation }
    });
  } catch (error) {
    console.error('Update reservation error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Cancel reservation
router.delete('/:id', async (req, res) => {
  try {
    const reservation = await Reservation.findByPk(req.params.id);
    if (!reservation) {
      return res.status(404).json({
        success: false,
        message: 'Reservation not found'
      });
    }

    if (reservation.status === 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Cannot cancel completed reservation'
      });
    }

    await reservation.update({ status: 'cancelled' });

    // Free up the table
    if (reservation.table_id) {
      await Table.update(
        { status: 'available' },
        { where: { id: reservation.table_id } }
      );
    }

    res.json({
      success: true,
      message: 'Reservation cancelled successfully'
    });
  } catch (error) {
    console.error('Cancel reservation error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get user's reservations
router.get('/user/my-reservations', async (req, res) => {
  try {
    const { customer_phone } = req.query;
    
    if (!customer_phone) {
      return res.status(400).json({
        success: false,
        message: 'Customer phone is required'
      });
    }

    const reservations = await Reservation.findAll({
      where: { customer_phone },
      include: [
        {
          model: Table,
          as: 'table',
          required: false
        }
      ],
      order: [['reservation_date', 'DESC'], ['reservation_time', 'DESC']]
    });

    res.json({
      success: true,
      data: { reservations }
    });
  } catch (error) {
    console.error('Get user reservations error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get today's reservations
router.get('/today', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    
    const reservations = await Reservation.findAll({
      where: { reservation_date: today },
      include: [
        {
          model: Table,
          as: 'table',
          required: false
        }
      ],
      order: [['reservation_time', 'ASC']]
    });

    // Group by status
    const grouped = {
      confirmed: reservations.filter(r => r.status === 'confirmed'),
      arrived: reservations.filter(r => r.status === 'arrived'),
      cancelled: reservations.filter(r => r.status === 'cancelled'),
      completed: reservations.filter(r => r.status === 'completed'),
      'no-show': reservations.filter(r => r.status === 'no-show')
    };

    res.json({
      success: true,
      data: { 
        reservations,
        grouped,
        stats: {
          total: reservations.length,
          confirmed: grouped.confirmed.length,
          arrived: grouped.arrived.length,
          cancelled: grouped.cancelled.length
        }
      }
    });
  } catch (error) {
    console.error('Get today reservations error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;