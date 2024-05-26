# CODETION

CODETION is a Django project that allows users to create, update, and manage quiz contests. Users can participate in contests and view the leaderboard.

## Features

- **User Authentication:** Users can register, login, and logout.
- **Quiz Contests:** Users can create new quiz contests, update existing contests, and delete contests.
- **Leaderboard:** Users can view the leaderboard for each contest, showing the top scorers.

## Requirements

- Python 3.x
- Django 3.x or higher
- Docker (optional, for running the project using Docker)

## Installation

### Running Locally

1. **Clone the repository:**

    ```bash
    git clone https://github.com/ilakshaygupt/CODETION-BACKEND
    cd quiz-contest
    ```

2. **Create a virtual environment:**

    ```bash
    python -m venv env
    ```

3. **Activate the virtual environment:**

    - On Windows:

        ```bash
        .\env\Scripts\activate
        ```

    - On macOS and Linux:

        ```bash
        source env/bin/activate
        ```

4. **Install the required packages:**

    ```bash
    pip install -r requirements.txt
    ```

5. **Apply migrations:**

    ```bash
    python manage.py migrate
    ```

6. **Create a superuser:**

    ```bash
    python manage.py createsuperuser
    ```

7. **Run the development server:**

    ```bash
    python manage.py runserver
    ```

8. **Access the application:**

    Open your web browser and go to `http://127.0.0.1:8000`.

### Running Using Docker

1. **Clone the repository:**

    ```bash
    git clone https://github.com/ilakshaygupt/CODETION-BACKEND
    cd quiz-contest
    ```

2. **Build and run the containers:**

    ```bash
    docker-compose up --build
    ```

3. **Access the application:**

    Open your web browser and go to `http://localhost:8000`.



## Contributing

Contributions to CODETION are welcome! If you encounter any issues or have suggestions for improvements, please feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.