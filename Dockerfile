FROM php:7.4-fpm
# copy the Composer PHAR from the Composer image into the PHP image
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
# Install dependencies
RUN apt-get update && apt-get install -y \
        libicu-dev \
        libzip-dev \
        zip \
        unzip \
    && docker-php-ext-configure intl \
    && docker-php-ext-install -j$(nproc) \
        intl \
        pdo_mysql \
        zip

# Set working directory
WORKDIR /var/www/html/authenticator

ENV COMPOSER_ALLOW_SUPERUSER=1

COPY ./composer.json ./

RUN composer install

COPY . .

# Set permissions
RUN chown -R www-data:www-data /var/www/html

# Expose port
EXPOSE 9000
