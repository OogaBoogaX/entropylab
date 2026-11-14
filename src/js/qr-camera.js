// A cancellable camera lifetime; no recording, storage, logging, or network.
export class CameraCapture {
  constructor({ getUserMedia, decode, stopDecode = () => {} }) {
    this.getUserMedia = getUserMedia;
    this.decode = decode;
    this.stopDecode = stopDecode;
    this.epoch = 0;
  }
  stop() {
    this.epoch++;
    clearTimeout(this.timer);
    // Decoder retirement is best-effort; camera and caller-owned transcript
    // cleanup must still run if it throws. The epoch rejects any late result.
    try { this.stopDecode(); } catch { /* Continue cleanup without logging data. */ }
    for (const track of this.stream?.getTracks() || []) track.stop();
    this.stream = null;
    if (this.video) {
      this.video.pause();
      this.video.srcObject = null;
      this.video = null;
    }
  }
  async start(video, deviceId, onFrame, onError = () => {}) {
    this.stop();
    const epoch = this.epoch;
    const stream = await this.getUserMedia({
      audio: false,
      video: deviceId
        ? { deviceId: { exact: deviceId } }
        : { facingMode: "environment" },
    });
    if (epoch !== this.epoch) {
      for (const t of stream.getTracks()) t.stop();
      return false;
    }
    const disconnected = () => {
      if (epoch !== this.epoch) return;
      this.stop();
      onError({ code: "CAMERA_DISCONNECTED" });
    };
    for (const track of stream.getTracks()) track.addEventListener?.("ended", disconnected, { once: true });
    this.stream = stream;
    this.video = video;
    video.srcObject = stream;
    try {
      await video.play();
    } catch (error) {
      if (epoch === this.epoch) this.stop();
      throw error;
    }
    if (epoch !== this.epoch) return false;
    const frame = async () => {
      if (epoch !== this.epoch) return;
      try {
        const value = await this.decode(video);
        if (epoch !== this.epoch) return;
        if (value) onFrame(value);
      } catch {
        if (epoch === this.epoch) {
          this.stop();
          onError();
        }
        return;
      }
      if (epoch === this.epoch) this.timer = setTimeout(frame, 180);
    };
    void frame();
    return true;
  }
}
