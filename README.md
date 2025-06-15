# iCook - AI-Powered Recipe Application 🍳
Access it ! https://icook.pythonanywhere.com/
A Flask-based web application that provides AI-powered recipe suggestions and cooking assistance using advanced language models through OpenRouter API.

## 🌟 Features

- **AI Recipe Generation**: Get personalized recipe suggestions using state-of-the-art AI models
- **User Authentication**: Secure login and registration system with password hashing
- **Admin Dashboard**: Comprehensive administrative interface for user management
- **Modern UI**: Clean, responsive, and intuitive user interface
- **Recipe Management**: Save and manage your favorite recipes
- **Security-First**: Built with security best practices and headers
- **Multi-Model Support**: Supports various AI models through OpenRouter

## 🛠️ Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite with proper schema management
- **AI Integration**: OpenRouter API with multiple AI model options
- **Frontend**: HTML5, CSS3, JavaScript
- **Authentication**: Werkzeug password hashing
- **Security**: Comprehensive security headers and session management

## 📋 Prerequisites

- Python 3.7 or higher
- Git (for cloning the repository)
- An OpenRouter API key (sign up at [OpenRouter](https://openrouter.ai/))

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/iCook.git
cd iCook
```

### 2. Create Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Environment Configuration
Create a `.env` file in the root directory with the following variables:

```env
# OpenRouter API Configuration
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Database Configuration
DATABASE_PATH=icook.db

# Flask Secret Key (change this to a random string)
SECRET_KEY=your_super_secret_key_here

# AI Model Configuration
AI_MODEL=meta-llama/llama-3.2-3b-instruct:free
MAX_TOKENS=1000
TEMPERATURE=0.7

# Admin Dashboard Configuration
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password_here
```

### 5. Run the Application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## 🎯 Usage

### For Regular Users
1. **Registration**: Create a new account on the registration page
2. **Login**: Access your personal dashboard
3. **Recipe Generation**: Use the AI-powered recipe generator with custom ingredients
4. **Profile Management**: Update your preferences and saved recipes

### For Administrators
1. **Admin Login**: Access the admin dashboard at `/admin`
2. **User Management**: View, edit, and manage user accounts
3. **System Monitoring**: Monitor application usage and user activities

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENROUTER_API_KEY` | Your OpenRouter API key | Required |
| `DATABASE_PATH` | Path to SQLite database | `icook.db` |
| `SECRET_KEY` | Flask secret key for sessions | Required |
| `AI_MODEL` | AI model to use | `meta-llama/llama-3.2-3b-instruct:free` |
| `MAX_TOKENS` | Maximum tokens for AI responses | `1000` |
| `TEMPERATURE` | AI creativity level (0.0-1.0) | `0.7` |
| `ADMIN_USERNAME` | Admin dashboard username | `admin` |
| `ADMIN_PASSWORD` | Admin dashboard password | Required |

### Available AI Models

The application supports various free AI models through OpenRouter:
- `google/gemma-2-9b-it:free`
- `meta-llama/llama-3.2-3b-instruct:free`
- `microsoft/wizardlm-2-8x22b:free`
- And many more premium models with API credits

## 📁 Project Structure

```
iCook/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── icook.db              # SQLite database (auto-created)
├── README.md             # Project documentation
├── static/               # Static files
│   └── css/             # Stylesheets
│       ├── icook.css    # Main application styles
│       ├── login.css    # Login page styles
│       ├── registration.css
│       ├── landingpage.css
│       ├── layout-fix.css
│       └── admin/       # Admin-specific styles
│           ├── admin.css
│           ├── admin-dashboard.css
│           ├── admin-edit-user.css
│           └── admin-user-detail.css
└── templates/           # HTML templates
    ├── base.html        # Base template
    ├── landingpage.html # Landing page
    ├── login.html       # User login
    ├── registration.html # User registration
    ├── icook.html       # Main application
    ├── confirm.html     # Confirmation pages
    └── admin_*.html     # Admin interface templates
```

## 🔒 Security Features

- **Password Hashing**: Secure password storage using Werkzeug
- **Session Management**: Secure session handling
- **Security Headers**: Comprehensive HTTP security headers
- **Input Validation**: Protection against common web vulnerabilities
- **Environment Variables**: Sensitive data stored securely

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch:
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. Make your changes and commit:
   ```bash
   git commit -m 'Add some amazing feature'
   ```
4. Push to the branch:
   ```bash
   git push origin feature/amazing-feature
   ```
5. Open a Pull Request

## 🐛 Troubleshooting

### Common Issues

1. **OpenRouter API Key Error**
   - Ensure your API key is valid and has sufficient credits
   - Check that the `.env` file is properly configured

2. **Database Issues**
   - Delete `icook.db` and restart the application to recreate the database
   - Ensure proper file permissions

3. **Import Errors**
   - Verify all dependencies are installed: `pip install -r requirements.txt`
   - Ensure you're using the correct Python environment

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OpenRouter](https://openrouter.ai/) for providing access to multiple AI models
- [Flask](https://flask.palletsprojects.com/) for the excellent web framework
- The open-source community for various libraries and tools used in this project

## 📞 Support

If you encounter any issues or have questions:
1. Check the [Issues](https://github.com/YOUR_USERNAME/iCook/issues) page
2. Create a new issue with detailed information
3. Contact the maintainers

---

**Made with ❤️ for food lovers and cooking enthusiasts!**
