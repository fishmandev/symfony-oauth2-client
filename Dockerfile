FROM php:7.4-fpm
RUN useradd -ms /bin/bash ubuntu && apt-get update && apt-get install -y \
git \
unzip \
&& php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" \
&& php composer-setup.php --install-dir=/bin --filename=composer \
&& php -r "unlink('composer-setup.php');" \
&& docker-php-ext-install pdo_mysql
USER ubuntu
WORKDIR /var/www/html