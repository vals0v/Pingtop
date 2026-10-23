# Maintainer: vals0v <https://github.com/vals0v/Pingtop>
pkgname=pingtop-git
pkgver=1.2.r0
pkgrel=1
pkgdesc="Interactive C++20 network monitor (Latency, MTR, Bandwidth & Tailscale)"
arch=('x86_64' 'aarch64')
url="https://github.com/vals0v/Pingtop"
license=('MIT')
depends=('glibc' 'gcc-libs')
makedepends=('git' 'cmake' 'gcc')
provides=('pingtop')
conflicts=('pingtop')
source=("${pkgname}::git+https://github.com/vals0v/Pingtop.git"
        "pingtop.install")
sha256sums=('SKIP'
            'SKIP')
install=pingtop.install

pkgver() {
    cd "${pkgname}"
    printf "1.2.r%s.g%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
    cmake -B build -S "${pkgname}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr
    cmake --build build -j$(nproc)
}

package() {
    DESTDIR="${pkgdir}" cmake --install build
}
