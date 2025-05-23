# 🛒 Micro Foods Market

**Micro Foods Market** is a containerized microservices-based backend system for a grocery store, developed using Flask, SQLite, and Docker. The project simulates a real-world e-commerce backend architecture with separate services handling inventory, orders, users, and authentication, supporting efficient communication and scalability.

## 🚀 Features

- **Microservice Architecture**: Independent Flask services for user management, inventory, orders, and authentication.
- **Database Integration**: Each service uses a dedicated SQLite database with proper data separation and RESTful API endpoints.
- **Dockerized Deployment**: Services are containerized using Docker for consistent local development and simplified deployment.
- **Inter-Service Communication**: Microservices interact using HTTP-based REST APIs to handle operations like placing an order or updating inventory.
- **Scalable Design**: Built to simulate distributed service design and scalable backend systems in a retail environment.

## 🛠️ Tech Stack

- **Languages**: Python
- **Framework**: Flask
- **Database**: SQLite
- **Tools**: Docker, REST APIs, Git

## 📦 Setup Instructions

```bash
# Clone the repository
git clone https://github.com/yourusername/micro-foods-market.git
cd micro-foods-market

# Start all microservices using Docker Compose
docker-compose up --build
```

## 📁 Microservices

- `inventory_service/`: Manages product stock and availability.
- `order_service/`: Handles customer orders and order status.
- `user_service/`: Manages user accounts and registration.
- `auth_service/`: Provides token-based authentication.

## 📬 Contact

Developed by **Harshit Kandpal**  
📧 hkandpal944@gmail.com
🌐 [harshitkandpal.xyz](https://harshitkandpal.xyz)  
💻 [github.com/HarshitK150](https://github.com/HarshitK150)
