FROM php:7.4-fpm
FROM composer

WORKDIR "/app"

COPY ./composer.json ./

RUN composer install

COPY . .