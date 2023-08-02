# UGA Bookstore




This repository contains the source code for a Django-based web application that allows users to browse 
and purchase books, manage their account, and view order history. It includes features like user authentication, 
book search, shopping cart, checkout, address management, and payment methods.



***Don't proceed any further without reading the blog entry. Key components have been explained there in order to use this application to the fullest.***


## Requirements

* Python-3.10
* Django
* Docker (Optional)


# Usage

Clone the repository
```bash
git clone https://github.com/dineshbodala/UGA-Bookstore
```
I would advice you to set up a virtual environment before running the code.

Install all the requirements 
```bash
pip install -r requirements.txt
```



```bash
python manage.py runserver
```
and access the app from [http://localhost:8000](http://localhost:8000) !!

# Usage Via Docker

Pulling Docker Image
```bash
docker pull dineshbodala/bookstore
```

Running using docker in detached mode
```bash
docker run -d -p 8888:8000 dineshbodala/bookstore
```
and access the app from [http://0.0.0.0:8888](http://localhost:8888) !!
