//
//  Ultimate_Noughts_and_Crosses_Server_Tests.swift
//  Ultimate Noughts and Crosses Server Tests
//
//  Created by Kyle Jessup on 2015-11-13.
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

import XCTest
import PerfectLib
@testable import UltimateNoughtsAndCrossesServer

class Ultimate_Noughts_and_Crosses_Server_Tests: XCTestCase {
    
    override func setUp() {
        super.setUp()
		
		let dirPath = PerfectServer.staticPerfectServer.homeDir() + serverSQLiteDBs
		let dir = Dir(dirPath)
		try! dir.create()
		
		let file = File(GAME_DB_PATH)
		if file.exists() {
			file.delete()
		}
		
		let gameState = GameState()
		gameState.initializeDatabase()
    }
    
    override func tearDown() {
        super.tearDown()
		
		let file = File(GAME_DB_PATH)
		if file.exists() {
			file.delete()
		}
    }
    
    func testInitialization() {
		
		let file = File(GAME_DB_PATH)
		let exists = file.exists()
		
		XCTAssert(exists)
    }
	
	func testCreatePlayer() {
		let playerNick = "player 1"
		let gs = GameState()
		let playerId = gs.createPlayer(playerNick)
		XCTAssert(playerId != INVALID_ID)
	}
	
	func testCreateGame() {
		
		let player1Nick = "player 1"
		let player2Nick = "player 2"
		let gs = GameState()
		let player1Id = gs.createPlayer(player1Nick)
		let player2Id = gs.createPlayer(player2Nick)
		
		XCTAssert(player1Id != INVALID_ID)
		XCTAssert(player2Id != INVALID_ID)
		
		let (gameId, fieldId) = gs.createGame(playerX: player1Id, playerO: player2Id)
		
		XCTAssert(gameId != INVALID_ID)
		XCTAssert(fieldId != INVALID_ID)
	}
	
	func testGetBoardIds() {
		
		let player1Nick = "player 1"
		let player2Nick = "player 2"
		let gs = GameState()
		let player1Id = gs.createPlayer(player1Nick)
		let player2Id = gs.createPlayer(player2Nick)
		
		XCTAssert(player1Id != INVALID_ID)
		XCTAssert(player2Id != INVALID_ID)
		
		let (gameId, fieldId) = gs.createGame(playerX: player1Id, playerO: player2Id)
		
		XCTAssert(gameId != INVALID_ID)
		XCTAssert(fieldId != INVALID_ID)
		
		for x in 0...MAX_X {
			for y in 0...MAX_Y {
				
				let boardId = gs.boardId(gameId, x: x, y: y)

				XCTAssert(boardId != INVALID_ID)
			}
		}
	}
	
	func testGetSlotIds() {
		
		let player1Nick = "player 1"
		let player2Nick = "player 2"
		let gs = GameState()
		let player1Id = gs.createPlayer(player1Nick)
		let player2Id = gs.createPlayer(player2Nick)
		
		XCTAssert(player1Id != INVALID_ID)
		XCTAssert(player2Id != INVALID_ID)
		
		let (gameId, fieldId) = gs.createGame(playerX: player1Id, playerO: player2Id)
		
		XCTAssert(gameId != INVALID_ID)
		XCTAssert(fieldId != INVALID_ID)
		
		for x in 0...MAX_X {
			for y in 0...MAX_Y {
				
				let boardId = gs.boardId(gameId, x: x, y: y)
				
				XCTAssert(boardId != INVALID_ID)
				
				for x in 0...MAX_X {
					for y in 0...MAX_Y {
						
						let slotId = gs.slotId(boardId, x: x, y: y)
						
						XCTAssert(slotId != INVALID_ID)
					}
				}
			}
		}
	}
	
	func testTurnSwitch() {
		
		let player1Nick = "player 1"
		let player2Nick = "player 2"
		let gs = GameState()
		let player1Id = gs.createPlayer(player1Nick)
		let player2Id = gs.createPlayer(player2Nick)
		
		XCTAssert(player1Id != INVALID_ID)
		XCTAssert(player2Id != INVALID_ID)
		
		let (gameId, fieldId) = gs.createGame(playerX: player1Id, playerO: player2Id)
		
		XCTAssert(gameId != INVALID_ID)
		XCTAssert(fieldId != INVALID_ID)
		
		for _ in 0..<5 {
			let id1 = gs.currentPlayer(gameId)
			XCTAssert(id1.0 == player1Id)
			XCTAssert(id1.1 == .Ex)
			
			gs.endTurn(gameId)
			
			let id2 = gs.currentPlayer(gameId)
			XCTAssert(id2.0 == player2Id)
			XCTAssert(id2.1 == .Oh)
			
			gs.endTurn(gameId)
		}
	}
	
	func testEndGameEx() {
		
		let player1Nick = "player 1"
		let player2Nick = "player 2"
		let gs = GameState()
		let player1Id = gs.createPlayer(player1Nick)
		let player2Id = gs.createPlayer(player2Nick)
		
		XCTAssert(player1Id != INVALID_ID)
		XCTAssert(player2Id != INVALID_ID)
		
		do {
			let (gameId, fieldId) = gs.createGame(playerX: player1Id, playerO: player2Id)
			
			XCTAssert(gameId != INVALID_ID)
			XCTAssert(fieldId != INVALID_ID)
			
			gs.endGame(gameId, winner: .Ex)
				
			let win = gs.gameWinner(gameId)
			XCTAssert(win == .ExWin)
		}
		
		do {
			let (gameId, fieldId) = gs.createGame(playerX: player1Id, playerO: player2Id)
			
			XCTAssert(gameId != INVALID_ID)
			XCTAssert(fieldId != INVALID_ID)
			
			gs.endGame(gameId, winner: .Oh)
			
			let win = gs.gameWinner(gameId)
			XCTAssert(win == .OhWin)
		}
	}
	
	func testBoardOwner() {
		
		let player1Nick = "player 1"
		let player2Nick = "player 2"
		let gs = GameState()
		let player1Id = gs.createPlayer(player1Nick)
		let player2Id = gs.createPlayer(player2Nick)
		XCTAssert(player1Id != INVALID_ID)
		XCTAssert(player2Id != INVALID_ID)
		let (gameId, _) = gs.createGame(playerX: player1Id, playerO: player2Id)
		// test all eight possible avenues
		// across top
		do {
			let boardId = gs.boardId(gameId, x: 0, y: 0)
			//xxx
			//xoo
			//oxo
			let sequence = [
				(PieceType.Ex, 0, 0), (PieceType.Oh, 1, 1), (PieceType.Ex, 2, 0),
				(PieceType.Oh, 2, 1), (PieceType.Ex, 1, 2), (PieceType.Oh, 0, 2),
				(PieceType.Ex, 0, 1), (PieceType.Oh, 2, 2), (PieceType.Ex, 1, 0)
			]
			for (p, x, y) in sequence {
				let owner = gs.boardOwner(boardId)
				XCTAssert(owner == .None)
				let slotId = gs.slotId(boardId, x: x, y: y)
				XCTAssert(slotId != INVALID_ID)
				let set = gs.setSlotOwner(slotId, type: p)
				XCTAssert(set == true, "While setting \(x) \(y)")
				let get = gs.slotOwner(slotId)
				XCTAssert(get == p)
			}
			let owner = gs.boardOwner(boardId)
			XCTAssert(owner == .Ex)
		}
		// across mid
		do {
			let boardId = gs.boardId(gameId, x: 1, y: 0)
			//xoo
			//xxx
			//oxo
			let sequence = [
				(PieceType.Ex, 0, 0), (PieceType.Oh, 1, 0), (PieceType.Ex, 2, 1),
				(PieceType.Oh, 2, 0), (PieceType.Ex, 1, 2), (PieceType.Oh, 0, 2),
				(PieceType.Ex, 0, 1), (PieceType.Oh, 2, 2), (PieceType.Ex, 1, 1)
			]
			for (p, x, y) in sequence {
				let owner = gs.boardOwner(boardId)
				XCTAssert(owner == .None)
				let slotId = gs.slotId(boardId, x: x, y: y)
				XCTAssert(slotId != INVALID_ID)
				let set = gs.setSlotOwner(slotId, type: p)
				XCTAssert(set == true, "While setting \(x) \(y)")
				let get = gs.slotOwner(slotId)
				XCTAssert(get == p)
			}
			let owner = gs.boardOwner(boardId)
			XCTAssert(owner == .Ex)
		}
		// across bottom
		do {
			let boardId = gs.boardId(gameId, x: 2, y: 0)
			//oxo
			//xoo
			//xxx
			let sequence = [
				(PieceType.Ex, 0, 2), (PieceType.Oh, 1, 1), (PieceType.Ex, 1, 0),
				(PieceType.Oh, 2, 1), (PieceType.Ex, 1, 2), (PieceType.Oh, 0, 0),
				(PieceType.Ex, 0, 1), (PieceType.Oh, 2, 0), (PieceType.Ex, 2, 2)
			]
			for (p, x, y) in sequence {
				let owner = gs.boardOwner(boardId)
				XCTAssert(owner == .None, "Owner was \(owner)")
				let slotId = gs.slotId(boardId, x: x, y: y)
				XCTAssert(slotId != INVALID_ID)
				let set = gs.setSlotOwner(slotId, type: p)
				XCTAssert(set == true, "While setting \(x) \(y)")
				let get = gs.slotOwner(slotId)
				XCTAssert(get == p)
			}
			let owner = gs.boardOwner(boardId)
			XCTAssert(owner == .Ex)
		}
		// down left
		do {
			let boardId = gs.boardId(gameId, x: 0, y: 1)
			//xoo
			//xox
			//xxo
			let sequence = [
				(PieceType.Ex, 0, 0), (PieceType.Oh, 1, 0), (PieceType.Ex, 2, 1),
				(PieceType.Oh, 2, 0), (PieceType.Ex, 1, 2), (PieceType.Oh, 1, 1),
				(PieceType.Ex, 0, 1), (PieceType.Oh, 2, 2), (PieceType.Ex, 0, 2)
			]
			for (p, x, y) in sequence {
				let owner = gs.boardOwner(boardId)
				XCTAssert(owner == .None, "Owner was \(owner)")
				let slotId = gs.slotId(boardId, x: x, y: y)
				XCTAssert(slotId != INVALID_ID)
				let set = gs.setSlotOwner(slotId, type: p)
				XCTAssert(set == true, "While setting \(x) \(y)")
				let get = gs.slotOwner(slotId)
				XCTAssert(get == p)
			}
			let owner = gs.boardOwner(boardId)
			XCTAssert(owner == .Ex)
		}
		// down mid
		do {
			let boardId = gs.boardId(gameId, x: 1, y: 1)
			//oxo
			//oxx
			//xxo
			let sequence = [
				(PieceType.Ex, 1, 0), (PieceType.Oh, 0, 0), (PieceType.Ex, 2, 1),
				(PieceType.Oh, 2, 0), (PieceType.Ex, 0, 2), (PieceType.Oh, 0, 1),
				(PieceType.Ex, 1, 1), (PieceType.Oh, 2, 2), (PieceType.Ex, 1, 2)
			]
			for (p, x, y) in sequence {
				let owner = gs.boardOwner(boardId)
				XCTAssert(owner == .None, "Owner was \(owner)")
				let slotId = gs.slotId(boardId, x: x, y: y)
				XCTAssert(slotId != INVALID_ID)
				let set = gs.setSlotOwner(slotId, type: p)
				XCTAssert(set == true, "While setting \(x) \(y)")
				let get = gs.slotOwner(slotId)
				XCTAssert(get == p)
			}
			let owner = gs.boardOwner(boardId)
			XCTAssert(owner == .Ex)
		}
		// down right
		do {
			let boardId = gs.boardId(gameId, x: 2, y: 1)
			//oxx
			//oox
			//xox
			let sequence = [
				(PieceType.Ex, 2, 0), (PieceType.Oh, 0, 0), (PieceType.Ex, 2, 1),
				(PieceType.Oh, 1, 1), (PieceType.Ex, 0, 2), (PieceType.Oh, 0, 1),
				(PieceType.Ex, 1, 0), (PieceType.Oh, 1, 2), (PieceType.Ex, 2, 2)
			]
			for (p, x, y) in sequence {
				let owner = gs.boardOwner(boardId)
				XCTAssert(owner == .None, "Owner was \(owner)")
				let slotId = gs.slotId(boardId, x: x, y: y)
				XCTAssert(slotId != INVALID_ID)
				let set = gs.setSlotOwner(slotId, type: p)
				XCTAssert(set == true, "While setting \(x) \(y)")
				let get = gs.slotOwner(slotId)
				XCTAssert(get == p)
			}
			let owner = gs.boardOwner(boardId)
			XCTAssert(owner == .Ex)
		}
		// diag from left
		do {
			let boardId = gs.boardId(gameId, x: 0, y: 2)
			//xxo
			//oxo
			//xox
			let sequence = [
				(PieceType.Ex, 0, 0), (PieceType.Oh, 2, 0), (PieceType.Ex, 1, 1),
				(PieceType.Oh, 2, 1), (PieceType.Ex, 0, 2), (PieceType.Oh, 0, 1),
				(PieceType.Ex, 1, 0), (PieceType.Oh, 1, 2), (PieceType.Ex, 2, 2)
			]
			for (p, x, y) in sequence {
				let owner = gs.boardOwner(boardId)
				XCTAssert(owner == .None, "Owner was \(owner)")
				let slotId = gs.slotId(boardId, x: x, y: y)
				XCTAssert(slotId != INVALID_ID)
				let set = gs.setSlotOwner(slotId, type: p)
				XCTAssert(set == true, "While setting \(x) \(y)")
				let get = gs.slotOwner(slotId)
				XCTAssert(get == p)
			}
			let owner = gs.boardOwner(boardId)
			XCTAssert(owner == .Ex)
		}
		// diag from right
		do {
			let boardId = gs.boardId(gameId, x: 1, y: 2)
			//oxx
			//oxo
			//xox
			let sequence = [
				(PieceType.Ex, 2, 2), (PieceType.Oh, 0, 0), (PieceType.Ex, 1, 1),
				(PieceType.Oh, 2, 1), (PieceType.Ex, 0, 2), (PieceType.Oh, 0, 1),
				(PieceType.Ex, 1, 0), (PieceType.Oh, 1, 2), (PieceType.Ex, 2, 0)
			]
			for (p, x, y) in sequence {
				let owner = gs.boardOwner(boardId)
				XCTAssert(owner == .None, "Owner was \(owner)")
				let slotId = gs.slotId(boardId, x: x, y: y)
				XCTAssert(slotId != INVALID_ID)
				let set = gs.setSlotOwner(slotId, type: p)
				XCTAssert(set == true, "While setting \(x) \(y)")
				let get = gs.slotOwner(slotId)
				XCTAssert(get == p)
			}
			let owner = gs.boardOwner(boardId)
			XCTAssert(owner == .Ex)
		}
	}
	
	func testGetBoard() {
		let player1Nick = "player 1"
		let player2Nick = "player 2"
		let gs = GameState()
		let player1Id = gs.createPlayer(player1Nick)
		let player2Id = gs.createPlayer(player2Nick)
		
		XCTAssert(player1Id != INVALID_ID)
		XCTAssert(player2Id != INVALID_ID)
		
		let (gameId, fieldId) = gs.createGame(playerX: player1Id, playerO: player2Id)
		
		XCTAssert(gameId != INVALID_ID)
		XCTAssert(fieldId != INVALID_ID)
		
		let boardId = gs.boardId(gameId, x: 0, y: 0)
		do {
			let slotId = gs.slotId(boardId, x: 0, y: 0)
			gs.setSlotOwner(slotId, type: .Ex)
		}
		do {
			let slotId = gs.slotId(boardId, x: 2, y: 2)
			gs.setSlotOwner(slotId, type: .Ex)
		}
		do {
			let slotId = gs.slotId(boardId, x: 2, y: 0)
			gs.setSlotOwner(slotId, type: .Oh)
		}
		
		let board = gs.getBoard(gameId, x: 0, y: 0)!
		let boardDesc = board.description
		print("\(boardDesc)")
		
		XCTAssert(boardDesc == "X_O\n___\n__X")
		
		do {
			let exTst = board[(0, 0)]
			XCTAssert(exTst == .Ex)
		}
		do {
			let exTst = board[(2, 2)]
			XCTAssert(exTst == .Ex)
		}
		do {
			let exTst = board[(2, 0)]
			XCTAssert(exTst == .Oh)
		}
	}
	
	func testGetField() {
		let player1Nick = "player 1"
		let player2Nick = "player 2"
		let gs = GameState()
		let player1Id = gs.createPlayer(player1Nick)
		let player2Id = gs.createPlayer(player2Nick)
		
		XCTAssert(player1Id != INVALID_ID)
		XCTAssert(player2Id != INVALID_ID)
		
		let (gameId, fieldId) = gs.createGame(playerX: player1Id, playerO: player2Id)
		
		XCTAssert(gameId != INVALID_ID)
		XCTAssert(fieldId != INVALID_ID)
		
		let boardId = gs.boardId(gameId, x: 0, y: 0)
		do {
			let slotId = gs.slotId(boardId, x: 0, y: 0)
			gs.setSlotOwner(slotId, type: .Ex)
		}
		do {
			let slotId = gs.slotId(boardId, x: 2, y: 2)
			gs.setSlotOwner(slotId, type: .Ex)
		}
		do {
			let slotId = gs.slotId(boardId, x: 2, y: 0)
			gs.setSlotOwner(slotId, type: .Oh)
		}
		
		let field = gs.getField(gameId)!
		
		print("\(field)")
		
		let board = field[(0, 0)]
		let boardDesc = board.description
		print("\(boardDesc)")
		
		XCTAssert(boardDesc == "X_O\n___\n__X")
		
		do {
			let exTst = board[(0, 0)]
			XCTAssert(exTst == .Ex)
		}
		do {
			let exTst = board[(2, 2)]
			XCTAssert(exTst == .Ex)
		}
		do {
			let exTst = board[(2, 0)]
			XCTAssert(exTst == .Oh)
		}
	}
}











