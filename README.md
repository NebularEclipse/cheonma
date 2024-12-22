# cheonma

Welcome to our Access Control System in Flask

## Usage

Create a python virtual environment
```
$ python -m venv venv
```

Activate the virtual environment (Windows)
```
$ ./venv/Scripts/activate
```

Initialize the database
```
$ flask --app cheonma init-db
```

Initialize the first admin
```
$ flask --app cheonma init-admin
```

Run the app (debug mode)
```
$ flask --app cheonma run --debug
```