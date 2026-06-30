# aarch64 counterpart of docker/builds. The x86_64 image carries a pile of
# multilib cross-compilers (gcc/g++ -4.8/-5/-11, clang-10/-18) that exist only
# to drive the extra-compiler build matrix, which does not run on aarch64. Here
# we only need the extras consumed by the aarch64 test matrix: golang for the
# bogo tests, a few common build tools, and a modern clang for the ASan build.
FROM $DOCKER_IMAGE_PARENT

VOLUME /builds/worker/checkouts
VOLUME /builds/worker/workspace
VOLUME /builds/worker/.cache

# Modern clang from the LLVM apt repo (focal has arm64 packages there).
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
    -o /etc/apt/trusted.gpg.d/apt.llvm.org.asc \
 && echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-18 main" \
    > /etc/apt/sources.list.d/llvm.list

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    clang-18 \
    libclang-rt-18-dev \
    cmake \
    libelf-dev \
    libdw-dev \
    libssl-dev \
    valgrind \
    clang-format-10 \
    libabigail-dev \
    abigail-tools \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get autoremove -y && apt-get clean -y

RUN update-alternatives --install /usr/bin/clang-format \
    clang-format $(which clang-format-10) 10

# Install golang for bogo tests (arm64 build).
RUN curl https://dl.google.com/go/go1.23.1.linux-arm64.tar.gz -sLf | tar xzf - -C $HOME
ENV PATH "$PATH:$HOME/go/bin"

# Set a default command for debugging.
CMD ["/bin/bash", "--login"]
