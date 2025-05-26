document.addEventListener('DOMContentLoaded', () => {
  const music = document.getElementById('bg-music');

  const tryPlay = () => {
    music.play()
      .then(() => {
        document.removeEventListener('click', tryPlay);
        document.removeEventListener('mousemove', tryPlay);
      })
      .catch(() => {
        // Autoplay blocked, wait for interaction
      });
  };

  tryPlay(); // initial try
  document.addEventListener('click', tryPlay);
  document.addEventListener('mousemove', tryPlay);
});
