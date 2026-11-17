// What the holder feels and hears while a card is on the iPhone, so a tap
// never seems to do nothing: a firm tap and a click the moment the card is
// found, a light tick about three times a second for as long as the card is
// being read, a double buzz when the card slips away, and a success tap when
// it is done (the card sheet adds its own chime and check mark). The ticks
// are Core Haptics where the iPhone has it, else UIKit's feedback
// generators; the click is a system sound, so the ring/silent switch mutes it.
import AudioToolbox
import CoreHaptics
import UIKit

final class TapFeedback {
  /// How often a tick plays while the card is being read.
  static let tickInterval: DispatchTimeInterval = .milliseconds(320)
  /// The system "Tink" sound.
  private static let foundSound: SystemSoundID = 1103

  private var engine: CHHapticEngine?
  private var tick: CHHapticPatternPlayer?
  private var timer: DispatchSourceTimer?
  private let light = UIImpactFeedbackGenerator(style: .light)
  private let firm = UIImpactFeedbackGenerator(style: .rigid)
  private let notice = UINotificationFeedbackGenerator()

  // Every method may be called from any queue; the work runs on the main one.

  /// The card was found: a firm tap and a click, then ticks until `stop`.
  func found() {
    DispatchQueue.main.async {
      self.firm.impactOccurred(intensity: 1)
      AudioServicesPlaySystemSound(Self.foundSound)
      self.startTicking()
    }
  }

  /// The card slipped away mid-read: the ticks stop and a warning buzz plays.
  func lost() {
    DispatchQueue.main.async {
      self.stopTicking()
      self.notice.notificationOccurred(.warning)
    }
  }

  /// The read finished: the ticks stop and a success tap plays.
  func succeeded() {
    DispatchQueue.main.async {
      self.stopTicking()
      self.notice.notificationOccurred(.success)
    }
  }

  /// The read ended some other way (an error or the sheet closed).
  func stop() {
    DispatchQueue.main.async {
      self.stopTicking()
    }
  }

  // MARK: Main queue only

  private func startTicking() {
    stopTicking()
    prepareEngine()
    light.prepare()
    let timer = DispatchSource.makeTimerSource(queue: .main)
    timer.schedule(deadline: .now() + Self.tickInterval, repeating: Self.tickInterval)
    timer.setEventHandler { [weak self] in self?.playTick() }
    timer.resume()
    self.timer = timer
  }

  private func stopTicking() {
    timer?.cancel()
    timer = nil
  }

  private func playTick() {
    if let engine, let tick {
      do {
        try engine.start()
        try tick.start(atTime: CHHapticTimeImmediate)
        return
      } catch {
        // Fall back to UIKit below.
      }
    }
    light.impactOccurred(intensity: 0.6)
    light.prepare()
  }

  /// Sets up Core Haptics once, when the iPhone has it.
  private func prepareEngine() {
    guard engine == nil, CHHapticEngine.capabilitiesForHardware().supportsHaptics else { return }
    do {
      let engine = try CHHapticEngine()
      engine.isAutoShutdownEnabled = true
      engine.resetHandler = { [weak self] in
        DispatchQueue.main.async { self?.tick = try? self?.engine.flatMap(Self.makeTick) }
      }
      try engine.start()
      self.engine = engine
      tick = try Self.makeTick(engine)
    } catch {
      engine = nil
      tick = nil
    }
  }

  private static func makeTick(_ engine: CHHapticEngine) throws -> CHHapticPatternPlayer {
    let event = CHHapticEvent(
      eventType: .hapticTransient,
      parameters: [
        CHHapticEventParameter(parameterID: .hapticIntensity, value: 0.45),
        CHHapticEventParameter(parameterID: .hapticSharpness, value: 0.7),
      ],
      relativeTime: 0
    )
    return try engine.makePlayer(with: CHHapticPattern(events: [event], parameters: []))
  }
}
