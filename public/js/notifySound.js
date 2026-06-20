class NotifySound {
  constructor() {
    this.audioPath = "/sounds/notice.mp3";
    this.unlocked = false;
  }

  unlock() {
    if (this.unlocked) return;

    const audio = new Audio(this.audioPath);

    audio.play()
      .then(() => {
        audio.pause();
        audio.currentTime = 0;
        this.unlocked = true;
      })
      .catch(() => {});
  }

  play() {
    if (!this.unlocked) return;

    const audio = new Audio(this.audioPath);
    audio.volume = 0.6;
    audio.play().catch(() => {});
  }
}

window.notifySound = new NotifySound();
