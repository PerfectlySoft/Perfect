//
//  GameState-Server.swift
//  Ultimate Noughts and Crosses
//
//  Created by Kyle Jessup on 2015-10-28.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//


import PerfectLib

extension GameState {
	
	func initializeDatabase() {
		do {
			let sqlite = self.db
			defer {
				sqlite.close()
			}
			// not sure what all to put in here yet
			try sqlite.execute("CREATE TABLE IF NOT EXISTS players (" +
				"id INTEGER PRIMARY KEY, nick TEXT)")
			try sqlite.execute("CREATE UNIQUE INDEX IF NOT EXISTS playersidx ON players (" +
				"nick)")
			
			// state indicates whose turn it is now
			// x and y, if not INVALID_ID, indicate which board must be played on
			try sqlite.execute("CREATE TABLE IF NOT EXISTS games (" +
				"id INTEGER PRIMARY KEY, state INTEGER, player_ex INTEGER, player_oh INTEGER, x INTEGER, y INTEGER)")
			
			try sqlite.execute("CREATE TABLE IF NOT EXISTS fields (" +
				"id INTEGER PRIMARY KEY, id_game INTEGER)")
			
			try sqlite.execute("CREATE TABLE IF NOT EXISTS boards (" +
				"id INTEGER PRIMARY KEY, id_field INTEGER, x INTEGER, y INTEGER, owner INTEGER)")
			
			try sqlite.execute("CREATE TABLE IF NOT EXISTS slots (" +
				"id INTEGER PRIMARY KEY, id_board INTEGER, x INTEGER, y INTEGER, owner INTEGER)")
			
		} catch let e {
			print("Exeption creating SQLite DB \(e)")
			File(GAME_DB_PATH).delete()
		}
	}
	
	private var db: SQLite {
		return try! SQLite(GAME_DB_PATH)
	}
	
	// Returns the player id
	func createPlayer(nick: String) -> Int {
		do {
			let sqlite = self.db
			defer {
				sqlite.close()
			}
			try sqlite.execute("INSERT INTO players (nick) VALUES (:1)") {
				(stmt:SQLiteStmt) -> () in
				try stmt.bind(1, nick)
			}
			let gameId = sqlite.lastInsertRowID()
			return gameId
		} catch { }
		return INVALID_ID
	}
	
	// Returns tuple of Game id and field id
	func createGame(playerX playerX: Int, playerO: Int) -> (Int, Int) {
		do {
			let sqlite = self.db
			defer {
				sqlite.close()
			}
			try sqlite.execute("BEGIN")
			try sqlite.execute("INSERT INTO games (state, player_ex, player_oh) VALUES (\(PieceType.Ex.rawValue), \(playerX), \(playerO)) ")
			let gameId = sqlite.lastInsertRowID()
			try sqlite.execute("INSERT INTO fields (id_game) VALUES (\(gameId))")
			let fieldId = sqlite.lastInsertRowID()
			try sqlite.execute("COMMIT")
			return (gameId, fieldId)
		} catch { }
		return (INVALID_ID, INVALID_ID)
	}
	
	func getBoard(gameId: Int, x: Int, y: Int) -> Board? {
		// board (id INTEGER PRIMARY KEY, id_field INTEGER, x INTEGER, y INTEGER, owner INTEGER)
		// slots (id INTEGER PRIMARY KEY, id_board INTEGER, x INTEGER, y INTEGER, owner INTEGER)
		let b = Board()
		do {
			let sqlite = self.db
			defer {
				sqlite.close()
			}
			let fieldId = self.fieldId(sqlite, gameId: gameId)
			guard fieldId != INVALID_ID else {
				return nil
			}
			let boardId = self.boardId(sqlite, fieldId: fieldId, x: x, y: y, orInsert: false)
			guard fieldId != INVALID_ID else {
				return nil
			}
			try sqlite.forEachRow("SELECT x, y, owner FROM slots WHERE id_board = \(boardId)") {
				(stmt:SQLiteStmt, Int) -> () in
				
				let x = stmt.columnInt(0)
				let y = stmt.columnInt(1)
				let owner = PieceType(rawValue: stmt.columnInt(2))!
				
				b[(x, y)] = owner
			}
			b.owner = self.boardOwner(sqlite, boardId: boardId)
		} catch { }
		return b
	}
	
	private func getBoard(sqlite: SQLite, fieldId: Int, x: Int, y: Int) -> Board? {
		// board (id INTEGER PRIMARY KEY, id_field INTEGER, x INTEGER, y INTEGER, owner INTEGER)
		// slots (id INTEGER PRIMARY KEY, id_board INTEGER, x INTEGER, y INTEGER, owner INTEGER)
		let b = Board()
		do {
			let boardId = self.boardId(sqlite, fieldId: fieldId, x: x, y: y, orInsert: false)
			guard fieldId != INVALID_ID else {
				return nil
			}
			try sqlite.forEachRow("SELECT x, y, owner FROM slots WHERE id_board = \(boardId)") {
				(stmt:SQLiteStmt, Int) -> () in
				
				let x = stmt.columnInt(0)
				let y = stmt.columnInt(1)
				let owner = PieceType(rawValue: stmt.columnInt(2))!
				
				b[(x, y)] = owner
			}
			b.owner = self.boardOwner(sqlite, boardId: boardId)
		} catch { }
		return b
	}
	
	func getField(gameId: Int) -> Field? {
		let f = Field()
		do {
			let sqlite = self.db
			defer {
				sqlite.close()
			}
			let fieldId = self.fieldId(sqlite, gameId: gameId)
			guard fieldId != INVALID_ID else {
				return nil
			}
			for x in 0..<3 {
				for y in 0..<3 {
					if let board = self.getBoard(sqlite, fieldId: fieldId, x: x, y: y) {
						f[(x, y)] = board
					}
				}
			}
		}
		return f
	}
	
	private func fieldId(sqlite: SQLite, gameId: Int) -> Int {
		var fieldId = INVALID_ID
		do {
			try sqlite.forEachRow("SELECT id FROM fields WHERE id_game = \(gameId)") {
				(stmt:SQLiteStmt, Int) -> () in
				fieldId = stmt.columnInt(0)
			}
		} catch { }
		return fieldId
	}
	
	private func validX(x: Int) -> Bool {
		return x <= MAX_X
	}
	
	private func validY(y: Int) -> Bool {
		return y <= MAX_Y
	}
	
	func boardId(gameId: Int, x: Int, y: Int) -> Int {
		guard validX(x) && validY(y) else {
			return INVALID_ID
		}
		var boardId = INVALID_ID
		do {
			let sqlite = self.db
			defer {
				sqlite.close()
			}
			try sqlite.execute("BEGIN")
			let fieldId = self.fieldId(sqlite, gameId: gameId)
			try sqlite.forEachRow("SELECT id FROM boards WHERE id_field = \(fieldId) AND x = \(x) AND y = \(y)") {
				(stmt:SQLiteStmt, Int) -> () in
				boardId = stmt.columnInt(0)
			}
			if boardId == INVALID_ID {
				try sqlite.execute("INSERT INTO boards (id_field, x, y, owner) VALUES (\(fieldId), \(x), \(y), 0)")
				boardId = sqlite.lastInsertRowID()
			}
			try sqlite.execute("COMMIT")
		} catch { }
		return boardId
	}
	
	private func boardId(sqlite: SQLite, fieldId: Int, x: Int, y: Int, orInsert: Bool) -> Int {
		var boardId = INVALID_ID
		do {
			let sqlite = self.db
			defer {
				sqlite.close()
			}
			try sqlite.forEachRow("SELECT id FROM boards WHERE id_field = \(fieldId) AND x = \(x) AND y = \(y)") {
				(stmt:SQLiteStmt, Int) -> () in
				boardId = stmt.columnInt(0)
			}
			if orInsert && boardId == INVALID_ID {
				try sqlite.execute("INSERT INTO boards (id_field, x, y, owner) VALUES (\(fieldId), \(x), \(y), 0)")
				boardId = sqlite.lastInsertRowID()
			}
		} catch { }
		return boardId
	}
	
	func slotId(boardId: Int, x: Int, y: Int) -> Int {
		guard validX(x) && validY(y) else {
			return INVALID_ID
		}
		var slotId = INVALID_ID
		do {
			let sqlite = self.db
			defer {
				sqlite.close()
			}
			try sqlite.execute("BEGIN")
			try sqlite.forEachRow("SELECT id FROM slots WHERE id_board = \(boardId) AND x = \(x) AND y = \(y)") {
				(stmt:SQLiteStmt, Int) -> () in
				slotId = stmt.columnInt(0)
			}
			if slotId == INVALID_ID {
				try sqlite.execute("INSERT INTO slots (id_board, x, y, owner) VALUES (\(boardId), \(x), \(y), 0)")
				slotId = sqlite.lastInsertRowID()
			}
			try sqlite.execute("COMMIT")
		} catch { }
		return slotId
	}
	
	func gameWinner(gameId: Int) -> PieceType {
		let winCheck = self.currentPlayer(gameId)
		if winCheck.1 == .ExWin || winCheck.1 == .OhWin {
			return winCheck.1
		}
		return .None
	}
	
	// Returns tuple of player ID and piece type for next move
	func currentPlayer(gameId: Int) -> (Int, PieceType, Int, Int) {
		let sqlite = self.db
		defer {
			sqlite.close()
		}
		return self.currentPlayer(sqlite, gameId: gameId)
	}
	
	// Returns tuple of player ID and piece type for next move
	private func currentPlayer(sqlite: SQLite, gameId: Int) -> (Int, PieceType, Int, Int) {
		var ret = (INVALID_ID, PieceType.None, INVALID_ID, INVALID_ID)
		do {
			try sqlite.forEachRow("SELECT state, player_ex, player_oh, x, y FROM games WHERE id = \(gameId)") {
				(stmt:SQLiteStmt, i:Int) -> () in
				
				let state = stmt.columnInt(0)
				let exId = stmt.columnInt(1)
				let ohId = stmt.columnInt(2)
				let x = stmt.columnInt(3)
				let y = stmt.columnInt(4)
				
				ret.1 = PieceType(rawValue: state)!
				ret.0 = ret.1 == .Ex ? exId : ohId
				ret.2 = x
				ret.3 = y
			}
		} catch { }
		return ret
	}
	
	// Returns tuple of player ID and piece type for next move
	func endTurn(gameId: Int) -> (Int, PieceType) {
		var ret = (INVALID_ID, PieceType.None)
		do {
			let sqlite = self.db
			defer {
				sqlite.close()
			}
			try sqlite.forEachRow("SELECT state, player_ex, player_oh FROM games WHERE id = \(gameId)") {
				(stmt:SQLiteStmt, i:Int) -> () in
				
				let state = stmt.columnInt(0)
				let exId = stmt.columnInt(1)
				let ohId = stmt.columnInt(2)
				
				let oldPiece = PieceType(rawValue: state)!
				
				ret.1 = oldPiece == .Ex ? .Oh : .Ex
				ret.0 = ret.1 == .Ex ? exId : ohId
			}
			try sqlite.execute("UPDATE games SET state = \(ret.1.rawValue) WHERE id = \(gameId)")
		} catch { }
		return ret
	}
	
	// Returns tuple of player ID and piece type for next move
	func setActiveBoard(gameId: Int, x: Int, y: Int) {
		do {
			let sqlite = self.db
			defer {
				sqlite.close()
			}
			try sqlite.execute("UPDATE games SET x = \(x), y = \(y) WHERE id = \(gameId)")
		} catch { }
	}
	
	func endGame(gameId: Int, winner: PieceType) {
		do {
			let sqlite = self.db
			defer {
				sqlite.close()
			}
			let winnerValue = winner == .Ex ? PieceType.ExWin : PieceType.OhWin
			try sqlite.execute("UPDATE games SET state = \(winnerValue.rawValue) WHERE id = \(gameId)")
		} catch { }
	}
	
	// Returns the winner of the indicated board.
	func boardOwner(boardId: Int) -> PieceType {
		let sqlite = self.db
		defer {
			sqlite.close()
		}
		return self.boardOwner(sqlite, boardId: boardId)
	}
	
	// Returns the winner of the indicated board.
	private func boardOwner(sqlite: SQLite, boardId: Int) -> PieceType {
		var ret = PieceType.None
		do {
			// see if it has an outright winner
			try sqlite.forEachRow("SELECT owner FROM boards WHERE id = \(boardId) AND owner != 0") {
				(stmt:SQLiteStmt, i:Int) -> () in
				
				let owner = stmt.columnInt(0)
				ret = PieceType(rawValue: owner)!
			}
			if ret == .None {
				// no outright winner
				// scan to see if someone has won
				
				// ex
				if self.scanAll(sqlite, boardId: boardId, type: .Ex) {
					self.setBoardOwner(sqlite, boardId: boardId, type: .Ex)
					ret = .Ex
				}// oh
				else if self.scanAll(sqlite, boardId: boardId, type: .Oh) {
					self.setBoardOwner(sqlite, boardId: boardId, type: .Oh)
					ret = .Oh
				}
			}
		} catch { }
		return ret
	}
	
	// Returns the owner of the indicated slot.
	func slotOwner(boardId: Int, x: Int, y: Int) -> PieceType {
		let sqlite = self.db
		defer {
			sqlite.close()
		}
		return self.slotOwner(sqlite, boardId: boardId, x: x, y: y)
	}
	
	// Returns the owner of the indicated slot.
	private func slotOwner(sqlite: SQLite, boardId: Int, x: Int, y: Int) -> PieceType {
		var ret = PieceType.None
		do {
			try sqlite.forEachRow("SELECT owner FROM slots WHERE id_board = \(boardId) AND x = \(x) AND y = \(y)") {
				(stmt:SQLiteStmt, i:Int) -> () in
				let owner = stmt.columnInt(0)
				ret = PieceType(rawValue: owner)!
			}
		} catch { }
		return ret
	}
	
	// Returns the owner of the indicated slot.
	func slotOwner(slotId: Int) -> PieceType {
		let sqlite = self.db
		defer {
			sqlite.close()
		}
		return self.slotOwner(sqlite, slotId: slotId)
	}
	
	// Returns the owner of the indicated slot.
	private func slotOwner(sqlite: SQLite, slotId: Int) -> PieceType {
		var ret = PieceType.None
		do {
			try sqlite.forEachRow("SELECT owner FROM slots WHERE id = \(slotId)") {
				(stmt:SQLiteStmt, i:Int) -> () in
				let owner = stmt.columnInt(0)
				ret = PieceType(rawValue: owner)!
			}
		} catch { }
		return ret
	}
	
	// Does sanity check. Returns false if the slot was already marked.
	// Updates the next active board.
	func setSlotOwner(slotId: Int, type: PieceType) -> Bool {
		do {
			let sqlite = self.db
			defer {
				sqlite.close()
			}
			try sqlite.execute("BEGIN")
			guard self.slotOwner(sqlite, slotId: slotId) == .None else {
				return false
			}
			try sqlite.execute("UPDATE slots SET owner = \(type.rawValue) WHERE id = \(slotId)")
			try sqlite.execute("COMMIT")
			return true
		} catch { }
		return false
	}
	
	private func scanAll(sqlite: SQLite, boardId: Int, type: PieceType) -> Bool {
		if scanCrossTop(sqlite, boardId: boardId, type: type) {
			return true
		}
		if scanCrossMid(sqlite, boardId: boardId, type: type) {
			return true
		}
		if scanCrossBottom(sqlite, boardId: boardId, type: type) {
			return true
		}
		if scanDownLeft(sqlite, boardId: boardId, type: type) {
			return true
		}
		if scanDownMid(sqlite, boardId: boardId, type: type) {
			return true
		}
		if scanDownRight(sqlite, boardId: boardId, type: type) {
			return true
		}
		if scanDiagLeft(sqlite, boardId: boardId, type: type) {
			return true
		}
		if scanDiagRight(sqlite, boardId: boardId, type: type) {
			return true
		}
		return false
	}
	
	private func scanCrossTop(sqlite: SQLite, boardId: Int, type: PieceType) -> Bool {
		// (id INTEGER PRIMARY KEY, id_board INTEGER, x INTEGER, y, INTEGER, owner INTEGER)
		let stat = "SELECT count(id) FROM slots WHERE id_board = \(boardId) AND owner = \(type.rawValue) " +
			"AND ((x = 0 AND y = 0)" +
			"OR (x = 1 AND y = 0)" +
			"OR (x = 2 AND y = 0))"
		var yes = false
		try! sqlite.forEachRow(stat) {
			(stmt:SQLiteStmt, _:Int) -> () in
			yes = 3 == stmt.columnInt(0)
		}
		return yes
	}
	
	private func scanCrossMid(sqlite: SQLite, boardId: Int, type: PieceType) -> Bool {
		// (id INTEGER PRIMARY KEY, id_board INTEGER, x INTEGER, y, INTEGER, owner INTEGER)
		let stat = "SELECT count(id) FROM slots WHERE id_board = \(boardId) AND owner = \(type.rawValue) " +
			"AND ((x = 0 AND y = 1)" +
			"OR (x = 1 AND y = 1)" +
			"OR (x = 2 AND y = 1))"
		var yes = false
		try! sqlite.forEachRow(stat) {
			(stmt:SQLiteStmt, _:Int) -> () in
			yes = 3 == stmt.columnInt(0)
		}
		return yes
	}
	
	private func scanCrossBottom(sqlite: SQLite, boardId: Int, type: PieceType) -> Bool {
		// (id INTEGER PRIMARY KEY, id_board INTEGER, x INTEGER, y, INTEGER, owner INTEGER)
		let stat = "SELECT count(id) FROM slots WHERE id_board = \(boardId) AND owner = \(type.rawValue) " +
			"AND ((x = 0 AND y = 2)" +
			"OR (x = 1 AND y = 2)" +
			"OR (x = 2 AND y = 2))"
		var yes = false
		try! sqlite.forEachRow(stat) {
			(stmt:SQLiteStmt, _:Int) -> () in
			yes = 3 == stmt.columnInt(0)
		}
		return yes
	}
	
	private func scanDownLeft(sqlite: SQLite, boardId: Int, type: PieceType) -> Bool {
		// (id INTEGER PRIMARY KEY, id_board INTEGER, x INTEGER, y, INTEGER, owner INTEGER)
		let stat = "SELECT count(id) FROM slots WHERE id_board = \(boardId) AND owner = \(type.rawValue) " +
			"AND ((x = 0 AND y = 0)" +
			"OR (x = 0 AND y = 1)" +
			"OR (x = 0 AND y = 2))"
		var yes = false
		try! sqlite.forEachRow(stat) {
			(stmt:SQLiteStmt, _:Int) -> () in
			yes = 3 == stmt.columnInt(0)
		}
		return yes
	}
	
	private func scanDownMid(sqlite: SQLite, boardId: Int, type: PieceType) -> Bool {
		// (id INTEGER PRIMARY KEY, id_board INTEGER, x INTEGER, y, INTEGER, owner INTEGER)
		let stat = "SELECT count(id) FROM slots WHERE id_board = \(boardId) AND owner = \(type.rawValue) " +
			"AND ((x = 1 AND y = 0)" +
			"OR (x = 1 AND y = 1)" +
			"OR (x = 1 AND y = 2))"
		var yes = false
		try! sqlite.forEachRow(stat) {
			(stmt:SQLiteStmt, _:Int) -> () in
			yes = 3 == stmt.columnInt(0)
		}
		return yes
	}
	
	private func scanDownRight(sqlite: SQLite, boardId: Int, type: PieceType) -> Bool {
		// (id INTEGER PRIMARY KEY, id_board INTEGER, x INTEGER, y, INTEGER, owner INTEGER)
		let stat = "SELECT count(id) FROM slots WHERE id_board = \(boardId) AND owner = \(type.rawValue) " +
			"AND ((x = 2 AND y = 0)" +
			"OR (x = 2 AND y = 1)" +
			"OR (x = 2 AND y = 2))"
		var yes = false
		try! sqlite.forEachRow(stat) {
			(stmt:SQLiteStmt, _:Int) -> () in
			yes = 3 == stmt.columnInt(0)
		}
		return yes
	}
	
	private func scanDiagLeft(sqlite: SQLite, boardId: Int, type: PieceType) -> Bool {
		// (id INTEGER PRIMARY KEY, id_board INTEGER, x INTEGER, y, INTEGER, owner INTEGER)
		let stat = "SELECT count(id) FROM slots WHERE id_board = \(boardId) AND owner = \(type.rawValue) " +
			"AND ((x = 0 AND y = 0)" +
			"OR (x = 1 AND y = 1)" +
			"OR (x = 2 AND y = 2))"
		var yes = false
		try! sqlite.forEachRow(stat) {
			(stmt:SQLiteStmt, _:Int) -> () in
			yes = 3 == stmt.columnInt(0)
		}
		return yes
	}
	
	private func scanDiagRight(sqlite: SQLite, boardId: Int, type: PieceType) -> Bool {
		// (id INTEGER PRIMARY KEY, id_board INTEGER, x INTEGER, y, INTEGER, owner INTEGER)
		let stat = "SELECT count(id) FROM slots WHERE id_board = \(boardId) AND owner = \(type.rawValue) " +
			"AND ((x = 2 AND y = 0)" +
			"OR (x = 1 AND y = 1)" +
			"OR (x = 0 AND y = 2))"
		var yes = false
		try! sqlite.forEachRow(stat) {
			(stmt:SQLiteStmt, _:Int) -> () in
			yes = 3 == stmt.columnInt(0)
		}
		return yes
	}
	
	private func setBoardOwner(sqlite: SQLite, boardId: Int, type: PieceType) {
		try! sqlite.execute("UPDATE boards SET owner = \(type.rawValue) WHERE id = \(boardId)")
	}
}




