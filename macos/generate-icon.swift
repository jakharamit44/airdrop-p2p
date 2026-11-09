import AppKit
import Foundation

func drawIcon(in ctx: CGContext, size: CGFloat) {
    ctx.setAllowsAntialiasing(true)
    ctx.setShouldAntialias(true)

    let scale = size / 1024.0

    // Apple macOS Icon Grid (1024 x 1024 canvas)
    // Standard icon body: 824 x 824 centered inside 100 pt margins
    let margin: CGFloat = 100.0 * scale
    let bodySize: CGFloat = size - 2 * margin
    let iconRect = CGRect(x: margin, y: margin, width: bodySize, height: bodySize)
    let cornerRadius: CGFloat = 185.0 * scale
    let squirclePath = CGPath(roundedRect: iconRect, cornerWidth: cornerRadius, cornerHeight: cornerRadius, transform: nil)

    // 1. Native macOS Drop Shadow under Squircle
    ctx.saveGState()
    ctx.setShadow(
        offset: CGSize(width: 0, height: -22.0 * scale),
        blur: 32.0 * scale,
        color: NSColor.black.withAlphaComponent(0.42).cgColor
    )
    ctx.addPath(squirclePath)
    ctx.setFillColor(NSColor(red: 0.015, green: 0.03, blue: 0.07, alpha: 1.0).cgColor)
    ctx.fillPath()
    ctx.restoreGState()

    // 2. Base Squircle Surface (Clipped)
    ctx.saveGState()
    ctx.addPath(squirclePath)
    ctx.clip()

    let colorSpace = CGColorSpaceCreateDeviceRGB()

    // Oceanic Deep Midnight / Sapphire Gradient (macOS Sequoia / Sonoma aesthetic)
    let bgColors = [
        NSColor(red: 0.06, green: 0.13, blue: 0.29, alpha: 1.0).cgColor, // Top
        NSColor(red: 0.027, green: 0.075, blue: 0.20, alpha: 1.0).cgColor, // Mid
        NSColor(red: 0.008, green: 0.024, blue: 0.08, alpha: 1.0).cgColor  // Bottom
    ] as CFArray
    let bgLocations: [CGFloat] = [0.0, 0.52, 1.0]
    if let bgGradient = CGGradient(colorsSpace: colorSpace, colors: bgColors, locations: bgLocations) {
        ctx.drawLinearGradient(
            bgGradient,
            start: CGPoint(x: size / 2, y: size - margin),
            end: CGPoint(x: size / 2, y: margin),
            options: []
        )
    }

    let centerX = size / 2.0
    // Optical center: slightly adjusted so 270° arc visual weight is balanced
    let centerY = size * 0.485

    // 3. Multi-layer Ambient Lighting
    if size >= 32 {
        // Outer diffuse cyan glow
        let outerGlowColors = [
            NSColor(red: 0.05, green: 0.65, blue: 1.00, alpha: 0.28).cgColor,
            NSColor(red: 0.00, green: 0.35, blue: 0.85, alpha: 0.10).cgColor,
            NSColor.clear.cgColor
        ] as CFArray
        if let outerGlow = CGGradient(colorsSpace: colorSpace, colors: outerGlowColors, locations: [0.0, 0.5, 1.0]) {
            ctx.drawRadialGradient(
                outerGlow,
                startCenter: CGPoint(x: centerX, y: centerY),
                startRadius: 0,
                endCenter: CGPoint(x: centerX, y: centerY),
                endRadius: 420.0 * scale,
                options: []
            )
        }

        // Inner core beacon glow
        let innerGlowColors = [
            NSColor(red: 0.40, green: 0.88, blue: 1.00, alpha: 0.45).cgColor,
            NSColor(red: 0.08, green: 0.55, blue: 0.95, alpha: 0.15).cgColor,
            NSColor.clear.cgColor
        ] as CFArray
        if let innerGlow = CGGradient(colorsSpace: colorSpace, colors: innerGlowColors, locations: [0.0, 0.4, 1.0]) {
            ctx.drawRadialGradient(
                innerGlow,
                startCenter: CGPoint(x: centerX, y: centerY),
                startRadius: 0,
                endCenter: CGPoint(x: centerX, y: centerY),
                endRadius: 200.0 * scale,
                options: []
            )
        }
    }

    // 4. Concentric AirDrop Radiating Waves
    func drawAirDropRing(
        radius: CGFloat,
        strokeWidth: CGFloat,
        color: NSColor,
        glowColor: NSColor
    ) {
        let sw: CGFloat
        if size <= 16 {
            sw = 1.3
        } else if size <= 32 {
            sw = 1.6
        } else if size <= 64 {
            sw = max(2.2, strokeWidth * scale)
        } else {
            sw = strokeWidth * scale
        }

        // Apple AirDrop standard 270° arc with 90° bottom gap (-45° to 225°)
        let startAngle = -45.0 * .pi / 180.0
        let endAngle = 225.0 * .pi / 180.0

        // Soft outer glow pass for larger icon representations
        if size >= 64 {
            ctx.saveGState()
            ctx.setLineCap(.round)
            ctx.setLineWidth(sw)
            ctx.setStrokeColor(glowColor.cgColor)
            ctx.setShadow(offset: .zero, blur: 14.0 * scale, color: glowColor.cgColor)
            ctx.addArc(
                center: CGPoint(x: centerX, y: centerY),
                radius: radius * scale,
                startAngle: startAngle,
                endAngle: endAngle,
                clockwise: false
            )
            ctx.strokePath()
            ctx.restoreGState()
        }

        // Crisp primary wave stroke
        ctx.saveGState()
        ctx.setLineCap(.round)
        ctx.setLineWidth(sw)
        ctx.setStrokeColor(color.cgColor)
        ctx.addArc(
            center: CGPoint(x: centerX, y: centerY),
            radius: radius * scale,
            startAngle: startAngle,
            endAngle: endAngle,
            clockwise: false
        )
        ctx.strokePath()
        ctx.restoreGState()

        // Subtle core specular highlight centerline on Retina displays
        if size >= 128 {
            ctx.saveGState()
            ctx.setLineCap(.round)
            ctx.setLineWidth(max(1.0, 3.8 * scale))
            ctx.setStrokeColor(NSColor(white: 1.0, alpha: 0.45).cgColor)
            let insetAngle: CGFloat = 6.0 * .pi / 180.0
            ctx.addArc(
                center: CGPoint(x: centerX, y: centerY),
                radius: radius * scale,
                startAngle: startAngle + insetAngle,
                endAngle: endAngle - insetAngle,
                clockwise: false
            )
            ctx.strokePath()
            ctx.restoreGState()
        }
    }

    if size <= 16 {
        // High-contrast pixel-tuned 16x16: 2 clean arcs and a center dot
        drawAirDropRing(
            radius: 260.0,
            strokeWidth: 36.0,
            color: NSColor(red: 0.35, green: 0.80, blue: 1.0, alpha: 1.0),
            glowColor: NSColor.clear
        )
        drawAirDropRing(
            radius: 140.0,
            strokeWidth: 38.0,
            color: NSColor(red: 0.75, green: 0.95, blue: 1.0, alpha: 1.0),
            glowColor: NSColor.clear
        )
    } else if size <= 32 {
        // High-contrast 32x32: 2 rings with crisp contrast and central node
        drawAirDropRing(
            radius: 270.0,
            strokeWidth: 36.0,
            color: NSColor(red: 0.35, green: 0.80, blue: 1.0, alpha: 1.0),
            glowColor: NSColor.clear
        )
        drawAirDropRing(
            radius: 150.0,
            strokeWidth: 38.0,
            color: NSColor(red: 0.75, green: 0.95, blue: 1.0, alpha: 1.0),
            glowColor: NSColor.clear
        )
    } else {
        // Standard 3 concentric wave arcs (Apple AirDrop geometry)
        // Outer Arc
        drawAirDropRing(
            radius: 285.0,
            strokeWidth: 34.0,
            color: NSColor(red: 0.30, green: 0.76, blue: 0.98, alpha: 0.95),
            glowColor: NSColor(red: 0.05, green: 0.60, blue: 1.00, alpha: 0.60)
        )
        // Middle Arc
        drawAirDropRing(
            radius: 195.0,
            strokeWidth: 36.0,
            color: NSColor(red: 0.46, green: 0.86, blue: 1.00, alpha: 0.98),
            glowColor: NSColor(red: 0.10, green: 0.70, blue: 1.00, alpha: 0.70)
        )
        // Inner Arc
        drawAirDropRing(
            radius: 108.0,
            strokeWidth: 38.0,
            color: NSColor(red: 0.74, green: 0.95, blue: 1.00, alpha: 1.00),
            glowColor: NSColor(red: 0.25, green: 0.82, blue: 1.00, alpha: 0.80)
        )
    }

    // 5. Central Radiant Beacon Orb
    let dotRadius: CGFloat
    if size <= 16 {
        dotRadius = 1.2
    } else if size <= 32 {
        dotRadius = 1.8
    } else {
        dotRadius = max(2.8, 28.0 * scale)
    }

    ctx.saveGState()
    ctx.setFillColor(NSColor.white.cgColor)
    if size >= 64 {
        ctx.setShadow(
            offset: .zero,
            blur: 20.0 * scale,
            color: NSColor(red: 0.35, green: 0.88, blue: 1.0, alpha: 1.0).cgColor
        )
    }
    ctx.fillEllipse(in: CGRect(x: centerX - dotRadius, y: centerY - dotRadius, width: dotRadius * 2, height: dotRadius * 2))
    ctx.restoreGState()

    // 6. Subtle Specular Highlight Rim along the squircle border (Glass edge reflection)
    ctx.addPath(squirclePath)
    ctx.setLineWidth(max(1.0, 2.0 * scale))
    let rimColors = [
        NSColor(white: 1.0, alpha: 0.32).cgColor,
        NSColor(white: 1.0, alpha: 0.06).cgColor
    ] as CFArray
    if let rimGrad = CGGradient(colorsSpace: colorSpace, colors: rimColors, locations: [0.0, 1.0]) {
        ctx.replacePathWithStrokedPath()
        ctx.clip()
        ctx.drawLinearGradient(
            rimGrad,
            start: CGPoint(x: size / 2, y: size - margin),
            end: CGPoint(x: size / 2, y: margin),
            options: []
        )
    }

    ctx.restoreGState() // restore squircle clip
}

func renderExactPng(pixels: Int) -> Data {
    let size = CGFloat(pixels)
    let colorSpace = CGColorSpaceCreateDeviceRGB()
    let bitmapInfo = CGImageAlphaInfo.premultipliedLast.rawValue
    guard let ctx = CGContext(
        data: nil,
        width: pixels,
        height: pixels,
        bitsPerComponent: 8,
        bytesPerRow: pixels * 4,
        space: colorSpace,
        bitmapInfo: bitmapInfo
    ) else {
        fatalError("Failed to create CGContext for \(pixels)x\(pixels)")
    }

    drawIcon(in: ctx, size: size)

    guard let cgImage = ctx.makeImage() else {
        fatalError("Failed to create CGImage")
    }

    let rep = NSBitmapImageRep(cgImage: cgImage)
    guard let pngData = rep.representation(using: .png, properties: [:]) else {
        fatalError("Failed to export PNG data")
    }

    return pngData
}

// Determine target output path for AppIcon.icns
let fileManager = FileManager.default
let scriptURL = URL(fileURLWithPath: CommandLine.arguments[0])
let scriptDir = scriptURL.deletingLastPathComponent().path
let defaultIcnsPath: String
if fileManager.fileExists(atPath: (scriptDir as NSString).appendingPathComponent("generate-icon.swift")) {
    defaultIcnsPath = (scriptDir as NSString).appendingPathComponent("AppIcon.icns")
} else if fileManager.fileExists(atPath: "macos/generate-icon.swift") {
    defaultIcnsPath = "macos/AppIcon.icns"
} else {
    defaultIcnsPath = (scriptDir as NSString).appendingPathComponent("AppIcon.icns")
}
let targetIcnsPath = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : defaultIcnsPath

let iconsetDir = URL(fileURLWithPath: "/tmp/AppIcon.iconset")
try? fileManager.removeItem(at: iconsetDir)
try fileManager.createDirectory(at: iconsetDir, withIntermediateDirectories: true)

// Canonical 10 Apple macOS Icon Resolutions
let iconSizes: [(String, Int)] = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024)
]

for (name, pixels) in iconSizes {
    let pngData = renderExactPng(pixels: pixels)
    let destURL = iconsetDir.appendingPathComponent(name)
    try pngData.write(to: destURL)
}

print("[+] Successfully generated all 10 canonical resolutions in /tmp/AppIcon.iconset")

// Compile iconset into ICNS using iconutil
let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
process.arguments = ["-c", "icns", iconsetDir.path, "-o", targetIcnsPath]

try process.run()
process.waitUntilExit()

if process.terminationStatus == 0 {
    print("[+] Successfully compiled ICNS to: \(targetIcnsPath)")
} else {
    fatalError("[-] iconutil failed with exit code \(process.terminationStatus)")
}
