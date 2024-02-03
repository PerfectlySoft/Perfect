import XCTest
import PerfectLib
@testable import PerfectMustache

class PerfectMustacheTests: XCTestCase {

	func testMustacheParser1() {
		let usingTemplate = "TOP {\n{{#name}}\n{{name}}{{/name}}\n}\nBOTTOM"
		do {
			let template = try MustacheParser().parse(string: usingTemplate)
			let d = ["name": "The name"] as [String: Any]

			let context = MustacheEvaluationContext(map: d)
			let collector = MustacheEvaluationOutputCollector()
			template.evaluate(context: context, collector: collector)

			XCTAssertEqual(collector.asString(), "TOP {\n\nThe name\n}\nBOTTOM")
		} catch {
			XCTAssert(false)
		}
	}

	func testMustacheLambda1() {
		let usingTemplate = "TOP {\n{{#name}}\n{{name}}{{/name}}\n}\nBOTTOM"
		do {
			let nameVal = "Me!"
			let template = try MustacheParser().parse(string: usingTemplate)
			let d = ["name": {(_: String, _: MustacheEvaluationContext) -> String in return nameVal }] as [String: Any]

			let context = MustacheEvaluationContext(map: d)
			let collector = MustacheEvaluationOutputCollector()
			template.evaluate(context: context, collector: collector)

			let result = collector.asString()
			XCTAssertEqual(result, "TOP {\n\n\(nameVal)\n}\nBOTTOM")
		} catch {
			XCTAssert(false)
		}
	}

	func testMustacheParser2() {
		let usingTemplate = "TOP {\n{{#name}}\n{{name}}{{/name}}\n}\nBOTTOM"
		do {
			let template = try MustacheParser().parse(string: usingTemplate)
			let d = ["name": "The name"] as [String: Any]

			let context = MustacheEvaluationContext(map: d)
			let collector = MustacheEvaluationOutputCollector()
			template.evaluate(context: context, collector: collector)

			XCTAssertEqual(collector.asString(), "TOP {\n\nThe name\n}\nBOTTOM")
		} catch {
			XCTAssert(false)
		}
	}

	func testMustacheParser3() {
		let templateText = "TOP {\n{{#name}}\n{{name}}{{/name}}\n}\nBOTTOM"
		do {
			let d = ["name": "The name"] as [String: Any]
			let context = MustacheEvaluationContext(templateContent: templateText, map: d)
			let collector = MustacheEvaluationOutputCollector()
			let responseString = try context.formulateResponse(withCollector: collector)
			XCTAssertEqual(responseString, "TOP {\n\nThe name\n}\nBOTTOM")
		} catch {
			XCTAssert(false)
		}
	}

	func testMustacheLambda2() {
		let usingTemplate = "TOP {\n{{#name}}\n{{name}}{{/name}}\n}\nBOTTOM"
		do {
			let nameVal = "Me!"
			let template = try MustacheParser().parse(string: usingTemplate)
			let d = ["name": {(_: String, _: MustacheEvaluationContext) -> String in return nameVal }] as [String: Any]

			let context = MustacheEvaluationContext(map: d)
			let collector = MustacheEvaluationOutputCollector()
			template.evaluate(context: context, collector: collector)

			let result = collector.asString()
			XCTAssertEqual(result, "TOP {\n\n\(nameVal)\n}\nBOTTOM")
		} catch {
			XCTAssert(false)
		}
	}

	func testPartials1() {
		let src = "{{> top }} {\n{{#name}}\n{{name}}{{/name}}\n}\n{{> bottom }}"
		let main = File("./foo.mustache")
		let top = File("./top.mustache")
		let bottom = File("./bottom.mustache")
		let d = ["name": "The name"] as [String: Any]

		defer {
			main.delete()
			top.delete()
			bottom.delete()
		}
		do {
			try main.open(.truncate)
			try top.open(.truncate)
			try bottom.open(.truncate)

			try main.write(string: src)
			try top.write(string: "TOP")
			try bottom.write(string: "BOTTOM")

			main.close()
			top.close()
			bottom.close()

			let context = MustacheEvaluationContext(templatePath: "./foo.mustache", map: d)
			let collector = MustacheEvaluationOutputCollector()
			let result = try context.formulateResponse(withCollector: collector)
			XCTAssertEqual(result, "TOP {\n\n\(d["name"]!)\n}\nBOTTOM")

		} catch {
			XCTAssert(false, "\(error)")
		}
	}

	func testDotNotation1() {
		let usingTemplate = "TOP {\n{{name.first}} {{name.last}}\n}\nBOTTOM"
		do {
			let template = try MustacheParser().parse(string: usingTemplate)
			let d = ["name": ["first": "The", "last": "name"]] as [String: Any]

			let context = MustacheEvaluationContext(map: d)
			let collector = MustacheEvaluationOutputCollector()
			template.evaluate(context: context, collector: collector)

			XCTAssertEqual(collector.asString(), "TOP {\nThe name\n}\nBOTTOM")
		} catch {
			XCTAssert(false)
		}
	}

	func testDotNotation2() {
		let usingTemplate = "TOP {\n{{foo.data.name.first}} {{foo.data.name.last}}\n}\nBOTTOM"
		do {
			let template = try MustacheParser().parse(string: usingTemplate)
			let d = ["foo": ["data": ["name": ["first": "The", "last": "name"]]]] as [String: Any]

			let context = MustacheEvaluationContext(map: d)
			let collector = MustacheEvaluationOutputCollector()
			template.evaluate(context: context, collector: collector)

			XCTAssertEqual(collector.asString(), "TOP {\nThe name\n}\nBOTTOM")
		} catch {
			XCTAssert(false)
		}
	}
}
