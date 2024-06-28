# User Management

## Overview

The User Management Express App is a simple web application that allows users to sign up, log in, and manage their profiles. It is built using Node.js and Express and uses a JSON file for data storage instead of a traditional database.

## Features

- User registration with username, email, and password
- User login with authentication
- User profile management (edit username, delete account)
- Password hashing for security
- Form validation
- Session management for user authentication
- Static file serving for CSS and other assets


## Installation

1. **Clone the repository**
    ```sh
    git clone https://github.com/yourusername/User-Management-Express-App.git
    cd User-Management
    ```

2. **Install dependencies**
    ```sh
    npm install
    ```

3. **Run the application**
    ```sh
    node app.js
    ```

4. **Access the application**
    Open your browser and navigate to `http://localhost:8080`.

## Usage

### User Registration

1. Navigate to the registration page.
2. Fill in your username, email, and password.
3. Click on the "Register" button.

### User Login

1. Navigate to the login page.
2. Fill in your email and password.
3. Click on the "Login" button.

### User Profile Management

1. After logging in, navigate to your profile.
2. Edit your username or delete your account as needed.

## Dependencies

- [express](https://www.npmjs.com/package/express)
- [express-session](https://www.npmjs.com/package/express-session)
- [method-override](https://www.npmjs.com/package/method-override)
- [bcrypt](https://www.npmjs.com/package/bcrypt)
- [uuid](https://www.npmjs.com/package/uuid)
- [express-validator](https://www.npmjs.com/package/express-validator)
- [ejs](https://www.npmjs.com/package/ejs)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

