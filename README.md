# Restaurant POS Backend

A comprehensive Restaurant Point of Sale (POS) backend system built with Node.js, Express, and MySQL using Sequelize ORM.

## Features

### Authentication & Authorization
- JWT-based authentication
- Role-based access control (Admin, Manager, Staff, User)
- Granular permissions system
- Secure password hashing with bcrypt

### Core Modules
- **User Management**: Staff management with role-based permissions
- **Table Management**: Table setup, status tracking, smart plug integration
- **Menu Management**: Dynamic menu with categories, subcategories, and variants
- **Order Management**: Complete order lifecycle with KOT printing
- **Session Management**: Gaming session tracking with billing
- **Reservation System**: Table booking and management
- **Billing & Payments**: Comprehensive billing with discounts and multiple payment methods
- **Device Control**: Smart plug and device monitoring
- **Printer Management**: Multi-printer setup with routing
- **Reports & Analytics**: Detailed reporting and business insights

### Database Schema
- **Users**: Staff and customer management
- **Tables**: Table configuration and status
- **Menu Items**: Product catalog with pricing
- **Orders & Order Items**: Order processing and tracking
- **Sessions**: Gaming/dining session management
- **Reservations**: Booking system
- **Devices**: Smart device control
- **Printers**: Printer configuration and management

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd resto-backend
```

2. Install dependencies:
```bash
npm install
```

3. Create MySQL database:
```sql
CREATE DATABASE restaurant_pos;
```

4. Configure environment variables:
```bash
cp .env.example .env
```

Edit `.env` with your database credentials and other settings.

5. Start the server:
```bash
# Development
npm run dev

# Production
npm start
```

## Environment Variables

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_NAME=restaurant_pos
DB_USER=root
DB_PASSWORD=your_password

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_here
JWT_EXPIRE=7d

# Server Configuration
PORT=5000
NODE_ENV=development

# Frontend URL
FRONTEND_URL=http://localhost:5173
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user
- `POST /api/auth/logout` - Logout

### Users
- `GET /api/users/staff` - Get all staff members (Admin only)
- `POST /api/users/staff` - Create staff member (Admin only)
- `PUT /api/users/staff/:id/permissions` - Update staff permissions (Admin only)
- `DELETE /api/users/staff/:id` - Delete staff member (Admin only)

### Tables
- `GET /api/tables` - Get all tables
- `GET /api/tables/:id` - Get single table
- `POST /api/tables` - Create table (Admin/Manager)
- `PUT /api/tables/:id` - Update table
- `PATCH /api/tables/:id/status` - Update table status
- `POST /api/tables/:id/plug` - Map smart plug to table
- `POST /api/tables/:id/plug/control` - Control smart plug

### Menu
- `GET /api/menu` - Get all menu items
- `GET /api/menu/:id` - Get single menu item
- `POST /api/menu` - Create menu item (Admin/Manager)
- `PUT /api/menu/:id` - Update menu item
- `PATCH /api/menu/:id/availability` - Toggle availability
- `GET /api/menu/structure/categories` - Get menu structure

### Orders
- `GET /api/orders` - Get all orders
- `GET /api/orders/:id` - Get single order
- `POST /api/orders` - Create order
- `PATCH /api/orders/:id/status` - Update order status
- `POST /api/orders/:id/kot` - Print KOT

### Sessions
- `GET /api/sessions` - Get all sessions
- `POST /api/sessions/start` - Start session
- `POST /api/sessions/:id/end` - End session
- `POST /api/sessions/:id/extend` - Extend session
- `GET /api/sessions/user/history` - Get user session history

### Reservations
- `GET /api/reservations` - Get all reservations
- `POST /api/reservations` - Create reservation
- `PATCH /api/reservations/:id/status` - Update reservation status
- `GET /api/reservations/today` - Get today's reservations
- `GET /api/reservations/user/my-reservations` - Get user reservations

### Billing
- `GET /api/billing/session/:sessionId` - Get session bill
- `POST /api/billing/session/:sessionId/discount` - Apply discount
- `POST /api/billing/session/:sessionId/payment` - Process payment
- `GET /api/billing/session/:sessionId/receipt` - Generate receipt

### Reports
- `GET /api/reports/dashboard` - Dashboard analytics
- `GET /api/reports/revenue/category` - Revenue by category
- `GET /api/reports/tables/performance` - Table performance
- `GET /api/reports/items/sales` - Item sales report
- `GET /api/reports/financial/summary` - Financial summary

### Devices
- `GET /api/devices` - Get all devices
- `POST /api/devices` - Create device (Admin/Manager)
- `POST /api/devices/:id/control` - Control device
- `PATCH /api/devices/:id/status` - Update device status

### Printers
- `GET /api/printers` - Get all printers
- `POST /api/printers` - Create printer (Admin/Manager)
- `POST /api/printers/:id/test` - Test printer
- `PATCH /api/printers/:id/toggle` - Toggle printer status

## Default User Roles & Permissions

### Admin
- Full system access
- Staff management
- All CRUD operations
- Financial reports
- System configuration

### Manager
- Table and order management
- Menu management
- Limited staff permissions
- Discounts up to 15%
- Reports access

### Staff
- Basic order creation
- Table status updates
- KOT printing
- Limited system access

### User
- Table booking
- Session tracking
- Personal billing history
- Reservation management

## Database Relationships

- Users → Orders (created_by)
- Users → Sessions (created_by)
- Tables → Sessions (current session)
- Tables → Devices (smart plugs)
- Orders → OrderItems (order details)
- MenuItems → OrderItems (product reference)
- Sessions → Tables (table assignment)

## Security Features

- JWT token authentication
- Password hashing with bcrypt
- Role-based access control
- Input validation with express-validator
- Rate limiting
- CORS protection
- Helmet security headers

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Run tests (if available)
npm test
```

## Production Deployment

1. Set `NODE_ENV=production`
2. Configure production database
3. Set secure JWT secret
4. Enable SSL/HTTPS
5. Configure reverse proxy (nginx)
6. Set up process manager (PM2)

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## License

This project is licensed under the ISC License.